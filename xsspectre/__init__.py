"""XSSpectre package.

⚠️ Authorization required: only scan systems you own or are explicitly permitted to test.
"""

from .reporting import ScanResult, VulnerabilityFinding

__all__ = ["ScanResult", "VulnerabilityFinding"]
__version__ = "0.1.0"
