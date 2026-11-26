"""The scan of S-Boot's allocator, on images made for the test.

The addresses are those the scan reads on real S-Boot images; the images here are not real ones:
they hold the signature and its literal pool, nothing else.

    python3 -m unittest discover -s tests
"""
from __future__ import annotations

import struct
import unittest

from sboot_util import _SPLIT_TAIL_SIGNATURE, find_large_heap_sentinel, find_large_heap_sentinels

N910C_HEAP_BASE = 0x24E00000
SM_T715_HEAP_BASE = 0x24F00000


def image(*pools: tuple[int, int, int]) -> bytes:
    """The signature, then each literal pool (sentinel, heap base, mode flag)."""
    out = bytearray()
    for sentinel, heap_base, mode_flag in pools:
        out += b"\0" * 0x100
        out += _SPLIT_TAIL_SIGNATURE
        out += struct.pack("<4I", sentinel, heap_base, mode_flag, sentinel + 16)
    return bytes(out) + b"\0" * 0x100


class Scan(unittest.TestCase):
    def test_the_note4_pool_is_found_by_default(self) -> None:
        sboot = image((0x23EC1048, N910C_HEAP_BASE, 0x240C0848))
        self.assertEqual(find_large_heap_sentinels(sboot), [(0x23EC1048, N910C_HEAP_BASE)])
        self.assertEqual(find_large_heap_sentinel(sboot), 0x23EC1048)

    def test_the_tab_s2_pool_needs_its_heap_base(self) -> None:
        sboot = image((0x23EC1048, SM_T715_HEAP_BASE, 0x240C0848))
        self.assertEqual(find_large_heap_sentinel(sboot, SM_T715_HEAP_BASE), 0x23EC1048)
        with self.assertRaisesRegex(ValueError, "the image holds: 0x24f00000"):
            find_large_heap_sentinel(sboot)

    def test_two_splits_are_refused(self) -> None:
        sboot = image((0x23EC1048, N910C_HEAP_BASE, 0x240C0848),
                      (0x23EC2048, N910C_HEAP_BASE, 0x240C0848))
        self.assertEqual(len(find_large_heap_sentinels(sboot)), 2)
        with self.assertRaisesRegex(ValueError, "yielded 2 valid targets"):
            find_large_heap_sentinel(sboot)

    def test_another_small_sentinel_is_not_a_split(self) -> None:
        sboot = bytearray(image((0x23EC1048, N910C_HEAP_BASE, 0x240C0848)))
        struct.pack_into("<I", sboot, len(sboot) - 0x100 - 4, 0x23EC1050)
        self.assertEqual(find_large_heap_sentinels(bytes(sboot)), [])

    def test_nothing_found_names_no_heap_base(self) -> None:
        with self.assertRaisesRegex(ValueError, "the image holds: none"):
            find_large_heap_sentinel(b"\0" * 0x2000)


if __name__ == "__main__":
    unittest.main()
