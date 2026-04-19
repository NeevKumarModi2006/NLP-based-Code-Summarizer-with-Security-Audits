import threading
from transformers import AutoTokenizer, AutoModelForSeq2SeqLM
import torch
import warnings

warnings.filterwarnings("ignore", message=".*Tried to instantiate class '__path__._path'.*")

class InferenceEngine:
    def __init__(self, model_name="Salesforce/codet5-base-multi-sum"):
        self.lock = threading.Lock()
        try:
            self.tokenizer = AutoTokenizer.from_pretrained(model_name, local_files_only=True)
            self.model = AutoModelForSeq2SeqLM.from_pretrained(model_name, local_files_only=True)
        except Exception:
            self.tokenizer = AutoTokenizer.from_pretrained(model_name)
            self.model = AutoModelForSeq2SeqLM.from_pretrained(model_name)

        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        self.model = self.model.to(self.device)

    def generate_summary(self, prompt: str, max_length=128):
        """this will generate a summary from the enriched prompt."""
        inputs = self.tokenizer(prompt, return_tensors="pt", truncation=True, max_length=512).to(self.device)

        with self.lock:
            with torch.no_grad():
                full_summary_ids = self.model.generate(
                    inputs["input_ids"],
                    max_length=64,
                    min_length=10,
                    num_beams=4,
                    repetition_penalty=2.0,
                    no_repeat_ngram_size=3,
                    early_stopping=True
                )

        summary = self.tokenizer.decode(full_summary_ids[0], skip_special_tokens=True).strip()
        
        lower = summary.lower()
        if lower.startswith("summarize "):
            summary = "Handles " + summary[10:].strip()
        elif lower.startswith("summary for a single"):
            summary = "Implements logic for a single" + summary[20:]
        elif lower.startswith("summary for "):
            summary = "Provides logic for " + summary[12:].strip()
            
        if len(summary) > 0:
            summary = summary[0].upper() + summary[1:]
            if not summary.endswith('.'):
                summary += '.'
                
        return summary
