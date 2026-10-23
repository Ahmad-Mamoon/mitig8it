"""Conservative precision gate shared by promotion and release evaluations.

Counts must be independent, reviewed predictions from a frozen holdout. A model's
own confidence is not evidence. Never round a confidence bound before gating it.
"""
from __future__ import annotations

import math
from typing import Any


MINIMUM_PRECISION_SAMPLES = 100
PRECISION_FLOOR = 0.95
WILSON_95_Z = 1.959963984540054


def wilson_interval(successes: int, total: int) -> tuple[float | None, float | None]:
    if type(successes) is not int or type(total) is not int or not 0 <= successes <= total:
        raise ValueError("precision counts must be integers with 0 <= successes <= total")
    if total == 0:
        return None, None
    p = successes / total
    z2 = WILSON_95_Z ** 2
    denominator = 1 + z2 / total
    centre = (p + z2 / (2 * total)) / denominator
    margin = WILSON_95_Z * math.sqrt((p * (1 - p) + z2 / (4 * total)) / total) / denominator
    return max(0.0, centre - margin), min(1.0, centre + margin)


def precision_gate(successes: int, total: int, *, unresolved: int = 0,
                   minimum_samples: int = MINIMUM_PRECISION_SAMPLES,
                   precision_floor: float = PRECISION_FLOOR) -> dict[str, Any]:
    """Require 100 reviewed predictions and a two-sided 95% Wilson lower bound >= .95.

    The fixed defaults are also policy floors: a caller may tighten, never relax,
    them. Unresolved judgments block promotion instead of disappearing from counts.
    """
    if type(minimum_samples) is not int or minimum_samples < MINIMUM_PRECISION_SAMPLES:
        raise ValueError("minimum_samples cannot be below 100")
    if (type(precision_floor) not in (int, float) or not math.isfinite(precision_floor)
            or not PRECISION_FLOOR <= precision_floor <= 1):
        raise ValueError("precision_floor must be finite and between 0.95 and 1")
    if type(unresolved) is not int or unresolved < 0:
        raise ValueError("unresolved must be a nonnegative integer")
    lower, upper = wilson_interval(successes, total)
    reasons = []
    if total < minimum_samples:
        reasons.append(f"minimum_precision_samples_not_met:{total}/{minimum_samples}")
    if lower is None or lower < precision_floor:
        reasons.append("precision_lower_bound_below_floor")
    if unresolved:
        reasons.append(f"unresolved_adjudications:{unresolved}")
    return {
        "passed": not reasons, "reasons": reasons,
        "reviewed_predictions": total, "correct_predictions": successes,
        "unresolved_predictions": unresolved,
        "precision": successes / total if total else None,
        "precision_wilson_95": [lower, upper],
        "minimum_samples": minimum_samples, "precision_floor": precision_floor,
    }
