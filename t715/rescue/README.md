# The loader's rescue: a patch to omarchy-tab-s2's `boot/`

`0001-the-loader-s-rescue.patch` adds one knob, `t715.paramrescue`, to the initramfs of
[omarchy-tab-s2](https://github.com/elkir0/omarchy-tab-s2), the tablet's 32-bit Linux. With the
knob on, a boot of that initramfs looks at PARAM before anything else, and when the loader it
finds there is not one known to work, writes the one that is. It is what makes BOOT and RECOVERY
a way back for a tablet whose only system is started by a loader in PARAM.

The same change is in omarchy-tab-s2's `main` since 2026-11-25. The patch is for a clone of the
1.0.5 release.

What it does, what the tablet taught, how the images are built and installed, and the rules:
[../docs/RESCUE.md](../docs/RESCUE.md).

The patch applies to omarchy-tab-s2 at `v1.0.5`. It changes four files:

| File | What the patch adds |
|---|---|
| `boot/initramfs/init` | the knob and `param_rescue()` |
| `boot/build-initramfs.sh` | `--paramrescue IMAGE`, `--paramrescue-stock SHA256`, `--paramrescue-extent BYTES`, `--paramrescue-also IMAGE` |
| `boot/tests/test_initramfs.sh` | fourteen scenarios of the rescue on a synthetic disk; the whole suite: 206 PASS |
| `boot/README.md` | the knob, and the section "The loader's rescue" |

The files it changes are omarchy-tab-s2's, GPL-2.0-or-later; so are the lines it adds.

## Applying it

```bash
git clone https://github.com/elkir0/omarchy-tab-s2
cd omarchy-tab-s2
git checkout v1.0.5
git apply /path/to/bnuuyloader/t715/rescue/0001-the-loader-s-rescue.patch
git diff --stat         # the four files
```

Then build the port's 32-bit kernel as its developer guide says (`docs/DEPLOY.md`), and the two
images as [../docs/RESCUE.md](../docs/RESCUE.md), section 4 says. Run the suite before any image
is written to a tablet:

```bash
bash boot/tests/test_initramfs.sh
```

It builds its own images in Docker and never touches a tablet. Run it on its own: while it runs,
no file of `boot/` may be edited, bash reads the script as it goes.

On omarchy-tab-s2's `main`, the knob is already there: nothing to apply.
