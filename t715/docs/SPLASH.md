# The boot screen: a picture in the forged logo

The first image the tablet shows at a power-on is drawn by S-Boot itself. It decodes `logo.jpg`
from PARAM and draws it, a pixel at a time, before it starts any kernel. It is the only place
where something can be shown before Omarchy's own splash, which comes 4.7 s after the kernel
starts. The forged logo is that file: it can carry a picture on the whole panel, and it is where
the exploit enters. This tells how S-Boot draws its logo, how a picture fits in a file that has
almost no room, and how to make a logo of your own.

The result, on the owner's tablet since 2026-11-25: their picture (`loader/art/splash-bnuuy-and-me.png`:
a white rabbit and a butterfly on a black background) fills the panel from the first moment of the
boot, then Omarchy's splash takes over. The loader's code is `kboot6`'s, byte for byte; only the
logo changed. That loader is called `kboot7`.

![The panel as the logo leaves it: a white rabbit and a pale butterfly, centred on black](../loader/art/splash-preview.png)

*The panel as S-Boot's logo leaves it (`loader/art/splash-preview.png`, made by `preview_logo.py`).
One red pixel is missing from it: the loader's own mark, section 6.*

How sure each fact is, as in [FINDINGS.md](FINDINGS.md): **[hardware]** seen on the tablet,
**[static]** read in S-Boot's code with the tools of `loader/scripts/`, **[emulator]** seen in the
Unicorn rehearsal only.

## 1. How S-Boot draws its logo [static]

Read on 2026-11-25 with `sbdis.py` and `callpath.py`.

| What | Where | What it does |
|---|---|---|
| `decode_and_draw` | 0x23E148D8 | decodes the JPEG and draws it, row by row, from the top left corner |
| the pixel writer | 0x23E14088 | one pixel: a 32-bit word at `fb + (1536 * y + x) * 4` |
| the panel's width, height and framebuffer | 0x23E6860C, 0x23E68610, 0x23E68614 | 1536, 2048, 0x67000000 |
| the 24 bits per pixel path | in the writer | stores `b0 \| b2 << 8 \| b1 << 16`: the decoded pixel's three bytes, in the order first, third, second |

- **No clipping, no scaling.** The image is drawn as it is, from the corner. Whatever a row holds
  past the panel's 1536th pixel lands on the next row's first pixels, one row early, and is drawn
  over by that row when its turn comes.
- **No test of the height.** The image is drawn to its last row, whether that row is on the panel
  or not.

## 2. The colours [hardware]

The writer stores the decoded pixel's bytes as first, third, second. What the panel then makes of
those 32 bits was not known until a picture was on the tablet. Three rules were possible; three
loaders were built, the same picture with the file's channels in another order each time:

| Image | `--order`: what the file's R, G, B carry | On the tablet, 2026-11-25 |
|---|---|---|
| `kboot7-cas1` | `2,0,1`: the picture's B, R, G | fired, Omarchy came up; the rabbit's inner ears, pink in the picture, came out green |
| `kboot7-cas2` | `0,2,1`: the picture's R, B, G | built, not tried |
| `kboot7-cas3` | `0,1,2`: the picture's own R, G, B | fired, Omarchy came up; the colours of the picture |

Green ears are what the rule "**the panel shows the decoded pixel as it is**" predicts for the
first image, and only that rule. So the file must carry the picture's own channels: `--order 0,1,2`,
the default of every tool. `preview_logo.py` assumes the same by default (`--assume stored`); its
two other assumptions are kept for a panel that would differ.

## 3. The two geometries

| | Narrow, the default | Wide, `--geometry wide` |
|---|---|---|
| The image | 310 x 13501 pixels | 2048 x 2049 pixels |
| The stride | 932 bytes | 6144 bytes |
| What the panel shows | a band of 310 pixels on the left; the rest stays black | the first 1536 columns of the first 2048 rows: the whole panel |
| The trapped block | row 13500, byte 912 | row 2048, the last one: block (256, 0) |
| The JPEG | 115,874 bytes | at most 131,072 bytes (0x20000) |
| The loader | `kboot6` | `kboot7` |

The principle does not change between the two. S-Boot decodes into the 12 MiB buffer at 0x24300000
and does not stop at its end: the row that starts at 0x24F00000, the DRAM heap's head, overflows
onto it ([FINDINGS.md](FINDINGS.md), section 4). In the narrow image that is row 13500; in the wide
one, row 2048, the last. The picture goes in the first 2048 rows and the first 1536 columns;
everything else is black.

In both images the false free block sits at file offset 0x20000, the loader's ARM32 code at
0x20100, stage 2 at 0x24000: the file member is 161,792 bytes either way. The wide JPEG must
therefore end before 0x20000.

## 4. Room in the file

With the Huffman tables of libjpeg, a black wide logo alone takes 116,288 of the 131,072 bytes:
14 KiB for a picture, half of what the figure of this one needs. Two things give room back.

**Tables built for the file** [emulator]. S-Boot's decoder reads the code lengths of each Huffman
table from the file (the DHT segments) and takes the symbols in their standard order, whatever
order the file lists them in. So the lengths can be chosen for a file that is black almost
everywhere: the shortest codes go to the values black uses. The file stays a JPEG that any decoder
reads. Four plans, named by the tables they change; the size of the black logo under each:

| Plan (`--tables`) | The tables changed | A black wide logo |
|---|---|---|
| `libjpeg` | none: libjpeg's tables | 116,288 bytes |
| `dc` | the DC tables | 91,872 bytes |
| `eob` | the end-of-block codes | 75,424 bytes |
| `all` | all four (the default) | 67,200 bytes |

**A picture made cheap.** Its near-black background is made truly black (`--black 14`: a pixel
whose brightest channel is at most 14 is black). Then the coefficients below two thresholds are
left out (`--luma-floor`, `--chroma-floor`): that is the figure's simplification. The owner was
shown three levels, 2 and 1, 3 and 2, 4 and 3, found no difference between them on the panel, and
took 4 and 3, the one that leaves the most room. With the plan `all` and that level,
`kboot7-cas3`'s JPEG is 116,552 bytes: 67,200 for the black and 49,352 for the figure.

## 5. What the decoder costs [emulator]

A wider image makes S-Boot's decoder work on more columns per row. Measured in the emulator, on
2026-11-25:

- It calls no allocator while it decodes: the heap is touched by the overflow of the last row, and
  by nothing else.
- It uses about 2 KiB of stack.
- Its working memory is anchored at about 0x240BD3AC and grows downwards by 24 bytes per pixel
  column: with 2048 columns it reaches 0x240B038C.
- It spends the same number of instructions on `kboot6`'s logo and on the picture's (326,818,489
  for `kboot7-cas3`): the boot is no slower.

## 6. The loader's mark

Once the forged heap has let it in, the loader's ARM32 code writes, for S-Boot's later requests,
the 16 bytes of a false heap block at 0x67B00000. That is inside the framebuffer: row 1877 of the
screen, pixel 512. On the black logo nobody could see it; on the picture it is one red pixel and
three nearly black ones, below the figure, from the loader until the kernel's splash. Measured in
the emulator: those 16 bytes are all the loader writes into the screen. The owner accepted it, and
the loader's code stayed `kboot6`'s. It could be moved past the panel's last row (0x67C00000, two
literals in `go:` of `KBOOT_SOURCE` in `scripts/split_source.py`); that was never built.

## 7. The probe, and why it has 2048 rows

To see a picture on the panel before any code runs with it, there is a probe: the same logo with
no trapped block and no loader (`--no-trap`). S-Boot then boots BOOT as on a stock tablet.

The probe **must stop at 2048 rows**. A logo of 2049 rows without the trap would draw its last row
over the heap head with 16 zero bytes, and S-Boot's `malloc_large` would then follow a null pointer
and never return: seen in the emulator. The tools refuse to build one. At 2048 rows the last row
ends exactly at 0x24F00000, and the heap is left as it was.

On a tablet that keeps the rescue in BOOT ([RESCUE.md](RESCUE.md)), a probe does not stay long:
the rescue finds a PARAM that holds neither the stock image nor a loader it knows, writes its own
loader back and restarts. That is what happened on the owner's tablet: the picture was seen, then
the rescue ran, and the tablet was back under arm64 35 s after the restart. To look at a probe at
leisure, name it to the rescue (`--paramrescue-also`).

## 8. On the tablet (2026-11-25)

| Step | What happened |
|---|---|
| The probe | the picture on the panel; the rescue put `kboot6` back; arm64 again 35 s after the restart |
| `kboot7-cas1` | the loader fired, the picture stayed until Omarchy's splash; the colours permuted (section 2) |
| `kboot7-cas3` | the loader fired; the colours of the picture; the owner found the splash right |
| A boot not marked up (the mark service disabled for one boot) | the loader handed the next two boots to the rescue, which left `kboot7-cas3` alone; arm64 again at the third |

Rehearsed before each write: the 27 situations of `kboot_cases.py`, twice, 27 of 27 each time; the
ledger against a real ring dump, 6 of 6.

## 9. Making a logo of your own

From `t715/loader/`, with the dumps in place and the block calibrated as [../README.md](../README.md),
section 4 says. Any picture Pillow reads is converted to RGB, scaled to the panel's height and
centred in the 1536 columns, on black. One that would then be wider than the panel (a landscape
picture) is refused: give `--scale`, as a share of the panel's height.

```
venv/bin/python -I scripts/logo_art.py PICTURE --trap out/calibrated_block.json --measure
```

prints the size of the JPEG under each plan, and writes nothing. Then:

```
venv/bin/python -I scripts/logo_art.py PICTURE --trap out/calibrated_block.json --out out/logo.jpg --luma-floor 4 --chroma-floor 3
venv/bin/python -I scripts/preview_logo.py out/logo.jpg out/preview.png
```

The preview is the panel as S-Boot's logo leaves it, 1536 x 2048. With `--decoder sboot` the logo
is read by S-Boot's own decoder in the emulator, about two minutes: the truth, where Pillow is an
approximation of it.

The loader, verified:

```
venv/bin/python -I scripts/build_kboot.py --prod --geometry wide --art PICTURE --luma-floor 4 --chroma-floor 3 --name kbootN --verify
```

`--verify` decodes the whole logo with S-Boot's decoder and **refuses** the image unless the 16
bytes at 0x24F00000 are the heap head the loader is forged for, and nothing was written past the
last row. A refused image is removed. Its log says:

```
the heap head is the one the loader is forged for; the 64 bytes after the last row are as before the decode
```

If the picture is too rich for the file, the builder refuses the image and says so (its JPEG
reaches 0x20000): raise the floors, or lower `--scale`.

The probe, to see the picture with no code behind it:

```
venv/bin/python -I scripts/build_kboot.py --prod --geometry wide --art PICTURE --luma-floor 4 --chroma-floor 3 --no-trap --name probeN
```

It builds the PARAM image and its logo only: no stage 2, no slot image.

Then rehearse and install as for any loader ([../README.md](../README.md), sections 5 and 6), and
tell the rescue about the new loader ([RESCUE.md](RESCUE.md)): a loader the rescue does not know is
replaced at the next boot that reaches BOOT.

To go back to the black logo: `t715-arm64-install loader out/kboot6.param`.
