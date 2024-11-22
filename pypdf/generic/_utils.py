import codecs
from typing import Dict, List, Tuple, Union
from .._codecs import _pdfdoc_encoding, _pdfdoc_encoding_rev
from .._utils import StreamType, b_, logger_warning, read_non_whitespace
from ..errors import STREAM_TRUNCATED_PREMATURELY, PdfStreamError
from ._base import ByteStringObject, TextStringObject

def encode_pdfdocencoding(unicode_string: str) -> bytes:
    """
    Encodes a string into the PDFDocEncoding.

    See Table D.2 in the PDF Reference for details.
    """
    retval = bytearray()
    for c in unicode_string:
        try:
            retval.append(_pdfdoc_encoding_rev[c])
        except KeyError:
            raise UnicodeEncodeError("pdfdocencoding", c, 0, 1, "does not exist in PDFDocEncoding")
    return bytes(retval)

def create_string_object(string: Union[str, bytes], forced_encoding: Union[None, str, List[str], Dict[int, str]]=None) -> Union[TextStringObject, ByteStringObject]:
    """
    Create a ByteStringObject or a TextStringObject from a string to represent the string.

    Args:
        string: The data being used
        forced_encoding: Typically None, or an encoding string

    Returns:
        A ByteStringObject

    Raises:
        TypeError: If string is not of type str or bytes.
    """
    pass