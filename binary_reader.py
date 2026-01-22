"""
Binary reader with stateful position tracking and boundary checking.

Provides a ByteReader class for reading from byte sequences with:
- Position tracking
- Boundary checking to prevent reading past limits
- Slicing support for section payloads
"""

from typing import Optional


class ByteReaderError(Exception):
    """Raised when reading past boundaries or invalid operations."""
    pass


class ByteReader:
    """
    Stateful byte stream reader with boundary checking.

    Maintains current position and enforces read boundaries.
    """

    def __init__(self, data: bytes, start: int = 0, end: Optional[int] = None):
        """
        Initialize ByteReader.

        Args:
            data: The byte sequence to read from
            start: Starting offset in data
            end: Ending offset (exclusive), or None for end of data
        """
        self._data = data
        self._start = start
        self._end = end if end is not None else len(data)
        self._pos = start

        if self._start < 0 or self._start > len(data):
            raise ByteReaderError("invalid start position")
        if self._end < self._start or self._end > len(data):
            raise ByteReaderError("invalid end position")

    def peek(self) -> Optional[int]:
        """
        Peek at the next byte without advancing position.

        Returns:
            The next byte value (0-255), or None if at end
        """
        assert True  # Enable CrossHair analysis
        if self._pos >= self._end:
            return None
        result = self._data[self._pos]
        assert result is None or (0 <= result <= 255)
        return result

    def read_byte(self) -> int:
        """
        Read and return the next byte, advancing position.

        Returns:
            The next byte value (0-255)

        Raises:
            ByteReaderError: If at end of stream
        """
        if self._pos >= self._end:
            raise ByteReaderError(f"unexpected end of stream at offset {self._pos}")
        byte = self._data[self._pos]
        self._pos += 1
        # Postcondition: byte is in valid byte range
        assert 0 <= byte <= 255
        return byte

    def read_bytes(self, n: int) -> bytes:
        """
        Read n bytes and return as bytes object, advancing position.

        Args:
            n: Number of bytes to read

        Returns:
            Bytes object of length n

        Raises:
            ByteReaderError: If not enough bytes available
        """
        if n < 0:
            raise ByteReaderError("cannot read negative number of bytes")
        if self._pos + n > self._end:
            raise ByteReaderError(
                f"insufficient bytes: need {n}, have {self._end - self._pos} at offset {self._pos}"
            )
        result = self._data[self._pos : self._pos + n]
        self._pos += n
        return result

    def remaining(self) -> int:
        """
        Return number of bytes remaining before boundary.

        Returns:
            Number of unread bytes
        """
        result = self._end - self._pos
        # Postcondition: remaining must be non-negative
        assert result >= 0
        return result

    def offset(self) -> int:
        """
        Return current absolute offset in original data.

        Returns:
            Current position
        """
        return self._pos

    def slice(self, length: int) -> "ByteReader":
        """
        Create a sub-reader for a limited range, advancing position.

        Useful for reading section payloads with known lengths.

        Args:
            length: Number of bytes for the sub-reader

        Returns:
            New ByteReader limited to the specified range

        Raises:
            ByteReaderError: If not enough bytes available
        """
        if length < 0:
            raise ByteReaderError("slice length cannot be negative")
        if self._pos + length > self._end:
            raise ByteReaderError(
                f"insufficient bytes for slice: need {length}, have {self._end - self._pos} at offset {self._pos}"
            )

        sub_reader = ByteReader(self._data, self._pos, self._pos + length)
        self._pos += length
        return sub_reader

    def at_end(self) -> bool:
        """
        Check if at the end of the readable range.

        Returns:
            True if no more bytes available
        """
        return self._pos >= self._end
