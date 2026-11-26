from pathlib import Path
import subprocess

from payload_layout import *

ROOT = Path(__file__).resolve().parent
A64_TARGET = "aarch64-none-elf"
C_FLAGS = ("-O2", "-ffreestanding", "-mgeneral-regs-only", "-mstrict-align",
           "-fno-stack-protector")

def address_defines(name: str, address: int) -> dict[str, int]:
    return {f"{name}_LO": address & 0xffff, f"{name}_HI": address >> 16}

def compile_object(source: Path, target: str, output: Path, *,
                   flags: tuple[str, ...] = (),
                   defines: dict[str, int] | None = None) -> None:
    definitions = [f"-D{name}={hex(value)}" for name, value in (defines or {}).items()]
    subprocess.run(["clang", f"--target={target}", *flags, *definitions,
                    "-c", str(source), "-o", str(output)], check=True)

def extract_binary(source: Path, output: Path,
                   section: str | None = None) -> bytes:
    section_flag = [f"--only-section={section}"] if section else []
    subprocess.run(["llvm-objcopy", *section_flag, "-O", "binary",
                    str(source), str(output)], check=True)
    return output.read_bytes()

def compile_a64(output: Path) -> tuple[bytes, bytes]:
    entry_obj = output / "a64_entry.o"
    elf = output / "a64.elf"
    compile_object(ROOT / "src/a64_entry.S", A64_TARGET, entry_obj,
                   defines=address_defines("A64_STACK_ADDRESS", A64_STACK_ADDRESS))
    objects = [entry_obj]
    for name in ("main", "emmc", "console", "fb", "boot_image"):
        obj = output / f"{name}.o"
        extra = ("-fno-unwind-tables", "-fno-asynchronous-unwind-tables",
                 "-I", str(ROOT / "src")) if name == "main" else ()
        compile_object(ROOT / f"src/{name}.c", A64_TARGET, obj,
                       flags=C_FLAGS + extra)
        objects.append(obj)
    boot_obj = output / "boot_el1.o"
    compile_object(ROOT / "src/boot_el1.S", A64_TARGET, boot_obj)
    objects.append(boot_obj)
    layout_symbols = [
        f"--defsym=PAYLOAD_BASE_ADDRESS={BASE_ADDRESS:#x}",
        f"--defsym=A64_ENTRY_OFFSET={A64_ENTRY_OFFSET:#x}",
        f"--defsym=MAIN_ENTRY_OFFSET={MAIN_ENTRY_OFFSET:#x}",
    ]
    # "ld.lld" on every system: Windows finds ld.lld.exe under that name itself.
    subprocess.run(["ld.lld", "-m", "aarch64elf", "-T",
                    str(ROOT / "src/a64.ld"), *layout_symbols, "-o", str(elf),
                    *map(str, objects)], check=True)
    return (extract_binary(elf, output / "a64_entry.bin", ".entry"),
            extract_binary(elf, output / "main.bin", ".main"))
