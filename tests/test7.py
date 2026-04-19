
def calculate_area(radius):
    """Calculates the area of a circle."""
    import math
    if radius < 0:
        return 0
    return math.pi * radius * radius

if __name__ == "__main__":
    print(calculate_area(5))
