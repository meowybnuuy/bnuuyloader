from __future__ import annotations

import struct

_SPLIT_TAIL_SIGNATURE = bytes.fromhex("10 20 42 e2 02 c0 6c e0 00 c0 83 e5 ee ff ff ea")

def find_large_heap_sentinels(sboot: bytes) -> list[tuple[int, int]]:
  """Every split of the allocator the signature finds, as (sentinel, heap_base).

  The code is the same on other Exynos 5433 devices; the heap base in its literal pool is not:
  0x24E00000 on the N910C, 0x24F00000 on the SM-T715."""
  candidates: list[tuple[int, int]] = []
  start = 0
  while (hit := sboot.find(_SPLIT_TAIL_SIGNATURE, start)) != -1:
    start = hit + 1
    literal = hit + len(_SPLIT_TAIL_SIGNATURE)
    if literal + 16 > len(sboot):
      continue
    sentinel, heap_base, mode_flag, small_sentinel = struct.unpack_from("<4I", sboot, literal)
    if (
      sentinel % 4 == 0
      and small_sentinel == sentinel + 16
      and mode_flag % 4 == 0
      and 0x23E00000 <= sentinel < 0x24000000
    ):
      candidates.append((sentinel, heap_base))
  return candidates

def find_large_heap_sentinel(sboot: bytes, heap_base: int = 0x24E00000) -> int:
  """The split whose literal pool holds HEAP_BASE: the N910C's unless said otherwise."""
  candidates = [sentinel for sentinel, base in find_large_heap_sentinels(sboot) if base == heap_base]
  if len(candidates) != 1:
    found = ", ".join(f"{base:#010x}" for _, base in find_large_heap_sentinels(sboot)) or "none"
    raise ValueError(
      f"S-Boot allocator signature yielded {len(candidates)} valid targets; expected one "
      f"(heap base {heap_base:#010x}; the image holds: {found})"
    )
  return candidates[0]
