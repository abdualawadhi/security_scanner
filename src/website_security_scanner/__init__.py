"""
Website Security Scanner package.
"""

from .analyzers import __version__ as __version__
from .main import LowCodeSecurityScanner

__all__ = [
    "LowCodeSecurityScanner",
    "__version__",
]
