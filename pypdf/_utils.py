"""Utility functions for PDF library."""
__author__ = 'Mathieu Fenniak'
__author_email__ = 'biziqe@mathieu.fenniak.net'
import functools
import logging
import re
import sys
import warnings
from dataclasses import dataclass
from datetime import datetime, timezone
from io import DEFAULT_BUFFER_SIZE, BytesIO
from os import SEEK_CUR
from typing import IO, Any, Dict, List, Optional, Pattern, Tuple, Union, cast, overload
from ._text_utils import b_, str_
if sys.version_info[:2] >= (3, 10):
    from typing import TypeAlias
else:
    from typing_extensions import TypeAlias
from .errors import STREAM_TRUNCATED_PREMATURELY, DeprecationError, PdfStreamError
TransformationMatrixType: TypeAlias = Tuple[Tuple[float, float, float], Tuple[float, float, float], Tuple[float, float, float]]
CompressedTransformationMatrix: TypeAlias = Tuple[float, float, float, float, float, float]
StreamType = IO[Any]
StrByteType = Union[str, StreamType]

def read_until_whitespace(stream: StreamType, maxchars: Optional[int]=None) -> bytes:
    """
    Read non-whitespace characters and return them.

    Stops upon encountering whitespace or when maxchars is reached.

    Args:
        stream: The data stream from which was read.
        maxchars: The maximum number of bytes returned; by default unlimited.

    Returns:
        The data which was read.
    """
    pass

def read_non_whitespace(stream: StreamType) -> bytes:
    """
    Find and read the next non-whitespace character (ignores whitespace).

    Args:
        stream: The data stream from which was read.

    Returns:
        The data which was read.
    """
    pass

def skip_over_whitespace(stream: StreamType) -> bool:
    """
    Similar to read_non_whitespace, but return a boolean if more than one
    whitespace character was read.

    Args:
        stream: The data stream from which was read.

    Returns:
        True if more than one whitespace was skipped, otherwise return False.
    """
    pass

def check_if_whitespace_only(value: bytes) -> bool:
    """
    Check if the given value consists of whitespace characters only.

    Args:
        value: The bytes to check.

    Returns:
        True if the value only has whitespace characters, otherwise return False.
    """
    pass

def read_until_regex(stream: StreamType, regex: Pattern[bytes]) -> bytes:
    """
    Read until the regular expression pattern matched (ignore the match).
    Treats EOF on the underlying stream as the end of the token to be matched.

    Args:
        regex: re.Pattern

    Returns:
        The read bytes.
    """
    pass

def read_block_backwards(stream: StreamType, to_read: int) -> bytes:
    """
    Given a stream at position X, read a block of size to_read ending at position X.

    This changes the stream's position to the beginning of where the block was
    read.

    Args:
        stream:
        to_read:

    Returns:
        The data which was read.
    """
    pass

def read_previous_line(stream: StreamType) -> bytes:
    """
    Given a byte stream with current position X, return the previous line.

    All characters between the first CR/LF byte found before X
    (or, the start of the file, if no such byte is found) and position X
    After this call, the stream will be positioned one byte after the
    first non-CRLF character found beyond the first CR/LF byte before X,
    or, if no such byte is found, at the beginning of the stream.

    Args:
        stream: StreamType:

    Returns:
        The data which was read.
    """
    pass

def mark_location(stream: StreamType) -> None:
    """Create text file showing current location in context."""
    pass
B_CACHE: Dict[Union[str, bytes], bytes] = {}
WHITESPACES = (b' ', b'\n', b'\r', b'\t', b'\x00')
WHITESPACES_AS_BYTES = b''.join(WHITESPACES)
WHITESPACES_AS_REGEXP = b'[' + WHITESPACES_AS_BYTES + b']'

def deprecate_with_replacement(old_name: str, new_name: str, removed_in: str) -> None:
    """Raise an exception that a feature will be removed, but has a replacement."""
    pass

def deprecation_with_replacement(old_name: str, new_name: str, removed_in: str) -> None:
    """Raise an exception that a feature was already removed, but has a replacement."""
    pass

def deprecate_no_replacement(name: str, removed_in: str) -> None:
    """Raise an exception that a feature will be removed without replacement."""
    pass

def deprecation_no_replacement(name: str, removed_in: str) -> None:
    """Raise an exception that a feature was already removed without replacement."""
    pass

def logger_error(msg: str, src: str) -> None:
    """
    Use this instead of logger.error directly.

    That allows people to overwrite it more easily.

    See the docs on when to use which:
    https://pypdf.readthedocs.io/en/latest/user/suppress-warnings.html
    """
    pass

def logger_warning(msg: str, src: str) -> None:
    """
    Use this instead of logger.warning directly.

    That allows people to overwrite it more easily.

    ## Exception, warnings.warn, logger_warning
    - Exceptions should be used if the user should write code that deals with
      an error case, e.g. the PDF being completely broken.
    - warnings.warn should be used if the user needs to fix their code, e.g.
      DeprecationWarnings
    - logger_warning should be used if the user needs to know that an issue was
      handled by pypdf, e.g. a non-compliant PDF being read in a way that
      pypdf could apply a robustness fix to still read it. This applies mainly
      to strict=False mode.
    """
    pass

def rename_kwargs(func_name: str, kwargs: Dict[str, Any], aliases: Dict[str, str], fail: bool=False) -> None:
    """
    Helper function to deprecate arguments.

    Args:
        func_name: Name of the function to be deprecated
        kwargs:
        aliases:
        fail:
    """
    pass

class classproperty:
    """
    Decorator that converts a method with a single cls argument into a property
    that can be accessed directly from the class.
    """

    def __init__(self, method=None):
        self.fget = method

    def __get__(self, instance, cls=None) -> Any:
        return self.fget(cls)

@dataclass
class File:
    from .generic import IndirectObject
    name: str
    data: bytes
    image: Optional[Any] = None
    indirect_reference: Optional[IndirectObject] = None

    def __str__(self) -> str:
        return f'{self.__class__.__name__}(name={self.name}, data: {_human_readable_bytes(len(self.data))})'

    def __repr__(self) -> str:
        return self.__str__()[:-1] + f', hash: {hash(self.data)})'

@dataclass
class ImageFile(File):
    from .generic import IndirectObject
    image: Optional[Any] = None
    indirect_reference: Optional[IndirectObject] = None

    def replace(self, new_image: Any, **kwargs: Any) -> None:
        """
        Replace the Image with a new PIL image.

        Args:
            new_image (PIL.Image.Image): The new PIL image to replace the existing image.
            **kwargs: Additional keyword arguments to pass to `Image.Image.save()`.

        Raises:
            TypeError: If the image is inline or in a PdfReader.
            TypeError: If the image does not belong to a PdfWriter.
            TypeError: If `new_image` is not a PIL Image.

        Note:
            This method replaces the existing image with a new image.
            It is not allowed for inline images or images within a PdfReader.
            The `kwargs` parameter allows passing additional parameters
            to `Image.Image.save()`, such as quality.
        """
        pass

@functools.total_ordering
class Version:
    COMPONENT_PATTERN = re.compile('^(\\d+)(.*)$')

    def __init__(self, version_str: str) -> None:
        self.version_str = version_str
        self.components = self._parse_version(version_str)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Version):
            return False
        return self.components == other.components

    def __lt__(self, other: Any) -> bool:
        if not isinstance(other, Version):
            raise ValueError(f'Version cannot be compared against {type(other)}')
        min_len = min(len(self.components), len(other.components))
        for i in range(min_len):
            self_value, self_suffix = self.components[i]
            other_value, other_suffix = other.components[i]
            if self_value < other_value:
                return True
            elif self_value > other_value:
                return False
            if self_suffix < other_suffix:
                return True
            elif self_suffix > other_suffix:
                return False
        return len(self.components) < len(other.components)