"""Text utility functions for PDF library."""
__author__ = 'Mathieu Fenniak'
__author_email__ = 'biziqe@mathieu.fenniak.net'

from typing import Union

def b_(s: Union[str, bytes]) -> bytes:
    """Convert string to bytes."""
    if isinstance(s, bytes):
        return s
    return s.encode('latin-1')

def str_(b: Union[str, bytes]) -> str:
    """Convert bytes to string."""
    if isinstance(b, str):
        return b
    return b.decode('latin-1')