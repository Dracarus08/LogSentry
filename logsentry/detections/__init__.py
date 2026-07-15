"""Detection rules. Each rule takes events and returns findings.

Rules are plain functions with a common signature so the engine can run them in
sequence and so each one can be tested in isolation.
"""

from .rules import ALL_DETECTIONS

__all__ = ["ALL_DETECTIONS"]
