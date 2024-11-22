import codecs
from typing import Dict, List, Tuple, Union
from .._codecs import _pdfdoc_encoding, _pdfdoc_encoding_rev
from .._utils import StreamType, b_, logger_warning, read_non_whitespace
from ..errors import STREAM_TRUNCATED_PREMATURELY, PdfStreamError
from ._base import ByteStringObject, TextStringObject

def read_hex_string_from_stream(stream: StreamType) -> str:
    """
    Read a hex string from a stream.

    Args:
        stream: A file object (with read and seek methods)

    Returns:
        The decoded string

    Raises:
        PdfStreamError: If the stream ends before finding a closing '>'
    """
    hex_str = b""
    while True:
        tok = stream.read(1)
        if not tok:
            raise PdfStreamError("Stream has ended unexpectedly")
        if tok == b">":
            break
        hex_str += tok

    # If odd number of digits, assume last digit is 0
    if len(hex_str) % 2 == 1:
        hex_str += b"0"

    # Convert hex to bytes
    try:
        hex_str = hex_str.replace(b" ", b"")  # Remove whitespace
        hex_bytes = bytes.fromhex(hex_str.decode())
        return hex_bytes.decode('latin1')  # Use latin1 to map bytes directly to chars
    except ValueError:
        return ""

def read_string_from_stream(stream: StreamType) -> str:
    """
    Read a string from a stream.

    Args:
        stream: A file object (with read and seek methods)

    Returns:
        The decoded string

    Raises:
        PdfStreamError: If the stream ends before finding a closing ')'
    """
    tok = stream.read(1)
    if not tok:
        raise PdfStreamError("Stream has ended unexpectedly")
    if tok != b"(":
        raise PdfStreamError("Stream has ended unexpectedly")

    parens = 1
    txt = b""
    while True:
        tok = stream.read(1)
        if not tok:
            raise PdfStreamError("Stream has ended unexpectedly")
        
        if tok == b"\\":  # Escape sequence
            tok = stream.read(1)
            if not tok:
                raise PdfStreamError("Stream has ended unexpectedly")
            if tok in b"01234567":  # Octal escape
                octal_str = tok
                for _ in range(2):
                    tok = stream.read(1)
                    if not tok or tok not in b"01234567":
                        break
                    octal_str += tok
                txt += bytes([int(octal_str.decode(), 8)])
            elif tok == b"\n":  # Line continuation
                continue
            elif tok == b"\r":  # Line continuation
                tok2 = stream.read(1)
                if tok2 == b"\n":  # Skip \r\n
                    continue
                stream.seek(-1, 1)  # Push back tok2
                continue
            else:  # Simple escape
                if tok == b"n":
                    txt += b"\n"
                elif tok == b"r":
                    txt += b"\r"
                elif tok == b"t":
                    txt += b"\t"
                elif tok == b"b":
                    txt += b"\b"
                elif tok == b"f":
                    txt += b"\f"
                else:
                    txt += tok  # Just add the escaped char
        elif tok == b"(":
            parens += 1
            txt += tok
        elif tok == b")":
            parens -= 1
            if parens == 0:
                break
            txt += tok
        else:
            txt += tok

    return txt.decode('latin1')

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