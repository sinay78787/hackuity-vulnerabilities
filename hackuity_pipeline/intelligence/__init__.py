"""Deterministic Vulnerability Intelligence reporting layer."""


def build_report_context(*args, **kwargs):
    from .report_context import build_report_context as implementation
    return implementation(*args, **kwargs)


def write_intelligence_dataset(*args, **kwargs):
    from .report_context import write_intelligence_dataset as implementation
    return implementation(*args, **kwargs)


__all__ = ["build_report_context", "write_intelligence_dataset"]
