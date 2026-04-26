"""Log-normalisation utilities for ranking signals."""

import math


def log_normalize(value: float, max_value: float) -> float:
    """Normalise value to [0, 1] using log scale: log(1+v) / log(1+max)."""
    if max_value <= 0:
        return 0.0
    if value <= 0:
        return 0.0
    return math.log(1 + value) / math.log(1 + max_value)


def normalize_series(values: list[float]) -> list[float]:
    """Log-normalise an entire series against its own maximum."""
    max_val = max(values) if values else 0
    return [log_normalize(v, max_val) for v in values]
