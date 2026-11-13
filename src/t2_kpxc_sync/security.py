"""Memory security and zero-disk-footprint utilities."""

from typing import Union


def scrub_bytes(buf: Union[bytearray, memoryview]) -> None:
    """Overwrites mutable memory buffer with zeroes immediately after use."""
    if isinstance(buf, (bytearray, memoryview)):
        for i in range(len(buf)):
            buf[i] = 0


class SecureBuffer:
    """Context manager for sensitive bytearray buffers that zeroes on exit."""

    def __init__(self, data: bytes):
        self._buf = bytearray(data)

    def __enter__(self) -> bytearray:
        return self._buf

    def __exit__(self, exc_type, exc_val, exc_tb):
        scrub_bytes(self._buf)
        return False
