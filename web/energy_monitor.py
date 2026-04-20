"""
energy_monitor.py - measures CPU, memory, and energy usage of a program.

Cross-platform:
  Linux  : reads Intel RAPL via /sys/class/powercap for real energy data.
  Windows / macOS : falls back to TDP-based estimation from CPU time.
"""

from __future__ import annotations

import os
import sys
import time
import threading
import contextlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import psutil


_DEFAULT_TDP_WATTS: float = float(os.environ.get("ENERGY_MONITOR_TDP_WATTS", 28.0))
_SAMPLE_INTERVAL_S: float = float(os.environ.get("ENERGY_MONITOR_INTERVAL_S", 0.5))
_RAPL_ROOT = "/sys/class/powercap/intel-rapl"


def _rapl_available() -> bool:
    return sys.platform == "linux" and os.path.isdir(_RAPL_ROOT)


def _read_rapl_microjoules() -> Optional[int]:
    """this will read the current total energy from all available RAPL domains."""
    if not _rapl_available():
        return None
    total = 0
    try:
        for entry in os.listdir(_RAPL_ROOT):
            energy_file = os.path.join(_RAPL_ROOT, entry, "energy_uj")
            if os.path.isfile(energy_file):
                with open(energy_file, "r") as f:
                    total += int(f.read().strip())
        return total
    except OSError:
        return None


@dataclass
class EnergyReading:
    timestamp: float
    cpu_percent: float
    memory_mb: float
    rapl_energy_uj: Optional[int] = None

    def __repr__(self) -> str:  # pragma: no cover
        energy_str = (
            f", rapl={self.rapl_energy_uj} uJ"
            if self.rapl_energy_uj is not None
            else ""
        )
        return (
            f"EnergyReading(t={self.timestamp:.3f}, "
            f"cpu={self.cpu_percent:.1f}%, "
            f"mem={self.memory_mb:.1f} MB"
            f"{energy_str})"
        )


@dataclass
class EnergyReport:
    """holds aggregated performance and energy stats for a completed measurement."""

    wall_time_s: float
    cpu_time_s: float
    peak_memory_mb: float
    avg_cpu_percent: float
    estimated_energy_j: float
    estimated_carbon_gco2: float
    rapl_supported: bool
    readings: List[EnergyReading] = field(default_factory=list)
    phase_timings: Dict[str, float] = field(default_factory=dict)

    def __str__(self) -> str:  # pragma: no cover
        lines = [
            "-" * 50,
            "  Energy & Performance Report",
            "-" * 50,
            f"  Wall time          : {self.wall_time_s:.3f} s",
            f"  CPU time           : {self.cpu_time_s:.3f} s",
            f"  Peak memory        : {self.peak_memory_mb:.1f} MB",
            f"  Avg CPU            : {self.avg_cpu_percent:.1f} %",
            f"  Estimated energy   : {self.estimated_energy_j:.4f} J",
            f"  RAPL hw counters   : {'yes' if self.rapl_supported else 'no (TDP estimate)'}",
            f"  Snapshots taken    : {len(self.readings)}",
        ]
        if self.phase_timings:
            lines.append("  Phase timings      :")
            for name, duration in self.phase_timings.items():
                lines.append(f"    {name:<20} {duration:.3f} s")
        lines.append("-" * 50)
        return "\n".join(lines)

    def to_dict(self) -> dict:
        """this will serialise the report to a plain dictionary."""
        return {
            "wall_time_s": self.wall_time_s,
            "cpu_time_s": self.cpu_time_s,
            "peak_memory_mb": self.peak_memory_mb,
            "avg_cpu_percent": self.avg_cpu_percent,
            "estimated_energy_j": self.estimated_energy_j,
            "estimated_carbon_gco2": getattr(self, "estimated_carbon_gco2", 0.0),
            "rapl_supported": self.rapl_supported,
            "phase_timings": self.phase_timings,
            "readings": [
                {
                    "timestamp": r.timestamp,
                    "cpu_percent": r.cpu_percent,
                    "memory_mb": r.memory_mb,
                    "rapl_energy_uj": r.rapl_energy_uj,
                }
                for r in self.readings
            ],
        }


class EnergyCollector:
    """
    this will collect periodic resource snapshots and produce an EnergyReport.
    a background daemon thread samples metrics at a set interval while
    the user's code runs on the main thread.
    """

    def __init__(
        self,
        sample_interval_s: float = _SAMPLE_INTERVAL_S,
        tdp_watts: float = _DEFAULT_TDP_WATTS,
    ) -> None:
        self._interval = sample_interval_s
        self._tdp = tdp_watts

        self._readings: List[EnergyReading] = []
        self._start_wall: float = 0.0
        self._start_cpu: psutil._common.pcputimes = None  # type: ignore[assignment]
        self._start_rapl_uj: Optional[int] = None

        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

        self._phase_timings: Dict[str, float] = {}
        self._current_phase: Optional[str] = None
        self._phase_start: float = 0.0

        self._proc = psutil.Process(os.getpid())
        self._lock = threading.Lock()
        self.report: Optional[EnergyReport] = None

    def start(self) -> "EnergyCollector":
        """this will begin measurement. must be called before stop()."""
        if self._thread is not None and self._thread.is_alive():
            raise RuntimeError("EnergyCollector is already running.  Call stop() first.")

        self._readings.clear()
        self._phase_timings.clear()
        self._current_phase = None
        self._stop_event.clear()
        self.report = None

        self._start_wall = time.perf_counter()
        self._start_cpu = self._proc.cpu_times()
        self._start_rapl_uj = _read_rapl_microjoules()

        self._proc.cpu_percent(interval=None)

        self._thread = threading.Thread(
            target=self._sample_loop,
            name="energy-monitor-sampler",
            daemon=True,
        )
        self._thread.start()
        return self

    def stop(self) -> EnergyReport:
        """this will stop measurement and return the aggregated EnergyReport."""
        if self._thread is None:
            raise RuntimeError("EnergyCollector has not been started.  Call start() first.")

        if self._current_phase is not None:
            self.end_phase()

        self._stop_event.set()
        self._thread.join(timeout=self._interval * 3)
        self._thread = None

        end_wall = time.perf_counter()
        end_cpu = self._proc.cpu_times()
        end_rapl_uj = _read_rapl_microjoules()

        wall_time_s = end_wall - self._start_wall
        cpu_time_s = (
            (end_cpu.user + end_cpu.system)
            - (self._start_cpu.user + self._start_cpu.system)
        )

        with self._lock:
            readings_snapshot = list(self._readings)

        peak_memory_mb = (
            max((r.memory_mb for r in readings_snapshot), default=0.0)
        )
        avg_cpu = (
            sum(r.cpu_percent for r in readings_snapshot) / len(readings_snapshot)
            if readings_snapshot
            else 0.0
        )

        rapl_supported = (
            self._start_rapl_uj is not None and end_rapl_uj is not None
        )
        if rapl_supported:
            delta_uj = end_rapl_uj - self._start_rapl_uj  # type: ignore[operator]
            if delta_uj < 0:
                delta_uj = 0
            estimated_energy_j = delta_uj / 1_000_000.0
        else:
            estimated_energy_j = self._estimate_energy_tdp(
                cpu_time_s=cpu_time_s,
                avg_cpu_percent=avg_cpu,
                wall_time_s=wall_time_s,
            )

        # Calculate estimated carbon emissions (approx global avg 475 gCO2eq/kWh)
        energy_kwh = estimated_energy_j / 3_600_000.0
        estimated_carbon_gco2 = energy_kwh * 475.0

        self.report = EnergyReport(
            wall_time_s=wall_time_s,
            cpu_time_s=cpu_time_s,
            peak_memory_mb=peak_memory_mb,
            avg_cpu_percent=avg_cpu,
            estimated_energy_j=estimated_energy_j,
            estimated_carbon_gco2=estimated_carbon_gco2,
            rapl_supported=rapl_supported,
            readings=readings_snapshot,
            phase_timings=dict(self._phase_timings),
        )
        return self.report

    def begin_phase(self, name: str) -> None:
        """this will mark the beginning of a named phase."""
        if self._current_phase is not None:
            self.end_phase()
        self._current_phase = name
        self._phase_start = time.perf_counter()

    def end_phase(self) -> None:
        """this will close the currently active phase and record its duration."""
        if self._current_phase is None:
            return
        elapsed = time.perf_counter() - self._phase_start
        self._phase_timings[self._current_phase] = (
            self._phase_timings.get(self._current_phase, 0.0) + elapsed
        )
        self._current_phase = None

    def _sample_loop(self) -> None:
        while not self._stop_event.is_set():
            self._collect_snapshot()
            self._stop_event.wait(timeout=self._interval)
        self._collect_snapshot()

    def _collect_snapshot(self) -> None:
        try:
            timestamp = time.time()
            raw_cpu_pct = self._proc.cpu_percent(interval=None)

            num_cores = psutil.cpu_count(logical=True) or 1
            cpu_pct = min(raw_cpu_pct / num_cores, 100.0)
            
            mem_info = self._proc.memory_info()
            memory_mb = mem_info.rss / (1024 * 1024)
            rapl_uj = _read_rapl_microjoules()
            reading = EnergyReading(
                timestamp=timestamp,
                cpu_percent=cpu_pct,
                memory_mb=memory_mb,
                rapl_energy_uj=rapl_uj,
            )
            with self._lock:
                self._readings.append(reading)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        except Exception:
            pass

    def _estimate_energy_tdp(
        self,
        cpu_time_s: float,
        avg_cpu_percent: float,
        wall_time_s: float,
    ) -> float:
        """this will estimate energy consumption in joules using a TDP-based model."""
        if cpu_time_s == 0:
            return 0.0
            
        util_fraction = max(avg_cpu_percent / 100.0, 0.01)
        energy_j = self._tdp * util_fraction * cpu_time_s
        
        return energy_j


@contextlib.contextmanager
def measure_energy(
    sample_interval_s: float = _SAMPLE_INTERVAL_S,
    tdp_watts: float = _DEFAULT_TDP_WATTS,
):
    """
    context manager for convenient energy/performance measurement.
    yields a started EnergyCollector, report is available on .report after exit.
    """
    collector = EnergyCollector(
        sample_interval_s=sample_interval_s,
        tdp_watts=tdp_watts,
    )
    collector.start()
    try:
        yield collector
    finally:
        if collector.report is None:
            collector.stop()


if __name__ == "__main__":
    import math

    print("Running built-in smoke test...\n")

    with measure_energy() as col:
        col.begin_phase("spin")
        deadline = time.perf_counter() + 2.0
        acc = 0.0
        while time.perf_counter() < deadline:
            acc += math.sqrt(time.perf_counter())
        col.end_phase()

        col.begin_phase("sleep")
        time.sleep(0.5)
        col.end_phase()

    print(col.report)
    print(f"\n[smoke-test] accumulator = {acc:.2f}  (prevents dead-code elimination)")
