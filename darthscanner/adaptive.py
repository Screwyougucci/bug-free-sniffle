"""Feedback-guided scheduling for bounded, benign HTTP fuzz cases."""
from __future__ import annotations

from collections import Counter
from typing import Sequence

# Signals guide the next *benign input family*; they never create payloads.
_SIGNAL_FAMILIES = {
    "input-reflection": {"encoding", "unicode", "punctuation", "structured-type"},
    "new-diagnostic-signature": {"structured-type", "type-mismatch", "numeric-type", "punctuation"},
    "new-server-error": {"type-mismatch", "numeric-type", "numeric-boundary", "structured-type"},
    "large-response-delta": {"length-boundary", "whitespace", "unicode"},
    "timing-outlier": {"length-boundary", "whitespace"},
    "status-change": {"type-mismatch", "boolean", "numeric", "encoding"},
    "content-type-change": {"structured-type", "encoding", "unicode"},
    "redirect": {"encoding", "path-shape", "type-mismatch"},
}


def choose_next_case(cases: Sequence[tuple], observations: Sequence) -> int:
    """Choose a pending (name, value, family) tuple using observed response signals.

    The scheduler rewards families associated with prior signals, explores
    under-tested families, and preserves corpus order as a deterministic tie-break.
    """
    if not cases:
        raise ValueError("cases must not be empty")
    family_counts = Counter(getattr(item, "case_family", "general") for item in observations)
    signal_weights: Counter[str] = Counter()
    for item in observations:
        signals = set(getattr(item, "signal_types", ()) or ())
        for signal in signals:
            for family in _SIGNAL_FAMILIES.get(signal, ()):
                signal_weights[family] += 3

    best_index = 0
    best_score = float("-inf")
    for index, case in enumerate(cases):
        family = case[2] if len(case) > 2 else "general"
        # Novelty prevents the scheduler from spending the whole budget in one family.
        score = signal_weights[family] - family_counts[family] * 2
        if family_counts[family] == 0:
            score += 1
        # Stable deterministic tie-break: earlier corpus cases win.
        score -= index * 0.001
        if score > best_score:
            best_score = score
            best_index = index
    return best_index
