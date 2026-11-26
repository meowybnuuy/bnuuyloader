> [!NOTE]
> bnuuyloader is not intended for normal users yet, for now, it is intended for advanced users and developers. I've also only tested this on the Note 4 Exynos (N910C), you will probably have to make your own changes to make your device work, PRs are very much appreciated. \
> \
> The Note 4 with Qualcomm SoC **WILL NOT** work, as it's SoC is ARM32 entirely, while Exynos SoC is ARM64 (but limited to ARM32 in software).

<p align="center"><img src="https://github.com/meowybnuuy/bnuuyloader/blob/main/bnuuy.gif?raw=true" width="128" height="128"></p>
<h1 align="center">bnuuyloader</h1>

Bnuuys have invaded the Exynos 5433 SoC, allowing it to run ARM64 code!

## Why make this and how does it work?
I like the Note 4 Exynos (specifically N910C) quite a lot, in my opinion, it represents one of the last ever best Android phones released, due to all of the features it has. But, there is a problem preventing the SoC from aging very well, Samsung intentionally limited the SoC to ARM32 (ARMv7) in software, despite the SoC supporting ARM64.

This means that any OS is forced to use legacy ARM32 (ARMv7), which has been slowly phased out over time, making software compatibility worsen over time.

Making matters worse, the software which makes the SoC start in ARM32 is apart of the boot process, specifically S-Boot, which is signed by Samsung and therefore cannot be modified by anyone but Samsung.

However, thanks to [UnsignedChad's CVE-2026-21155](https://github.com/UnsignedChad/CVE-2026-21155-SVE-2026-3546), we can get code execution inside S-Boot, which runs in EL2, letting us run our own code early enough to switch the SoC back into ARM64 and implement our own tiny bootloader!

## Caveats
- Trusted Firmware-A does not exist, you will have to use legacy SMC calls to bring up the other cores, which means they will startup in ARM32 and you'll have to switch them to ARM64. This is very hacky, but it works. Also, the boot core is Cortex-A53.
- The bootloader is probably not very good, it was just enough to boot mainline Linux just enough in an Android boot image. My hope is that by getting this out, that it can be improved by others.
- Probably others I am forgetting...

## Other devices

- **Galaxy Tab S2 8.0 LTE (SM-T715)**: a port is in [`t715/`](t715/README.md), with a loader of its own for this tablet's S-Boot. That loader hands control back to S-Boot when it has nothing to start, reads the kernel through S-Boot's own eMMC reader and starts it only if a hash matches, keeps the kernel in two slots of the CACHE partition, and gives the tablet back to its own kernel after a failed boot. It starts the tablet with all eight cores in 64 bits, every day. What was found about this S-Boot and about arm64 Linux on it is in [`t715/docs/FINDINGS.md`](t715/docs/FINDINGS.md).

## Building
To build a PARAM image (which contains bnuuyloader), you will need the `sboot.bin` and `param.bin` for your device (the S-Boot and PARAM must match the firmware on your device). You will also need LLVM/Clang to crosscompile the AArch32/AArch64 parts of bnuuyloader, as well as Python to run the build script.

You first need to install the dependencies `python3 -m pip install -r requirements.txt`, then you can run `python3 build.py --stock-param <path to original param> --sboot <path to original sboot>`. If everything goes right, it should build a `PARAM_bnuuyloader.tar`, which you can flash using Odin.

This has only been tested on the Note 4 Exynos, with firmware `N910CXXS2DRI2`, it may need adjusting for other firmwares, you may need to edit `payload_layout.py` if any issues occur.

The allocator's signature is the same code on other Exynos 5433 devices, but the heap base in the literal pool after it is not: `build.py --heap-base 0x24F00000` finds the place in the SM-T715's S-Boot, where the default refuses and names the heap base it met.

Please bare in mind that bnuuyloader does not support booting AArch32 kernels, it is assumed that you are using bnuuyloader to only run AArch64 kernels, as that is the main point of bnuuyloader.

To boot an AArch64 kernel, you need to wrap it in an Android boot image (`boot.img`) and flash it to your device using Odin. However, you can also just change the boot image loading behavior to suit your needs better.

## LLM disclosure
Unfortunately, I must admit that LLM assistance was used in the making of bnuuyloader. If you are turned off by this, I am sorry. My intent *was/is* to get this out there so that perhaps more cleaner implementations could be done, it shouldn't be that painful. PRs are appreciated if you'd like to clean it up, although I feel as if this code is already pretty clean. In the middle of attempting to clean this project up, my Note 4 Exynos died.

My hope is that by disclosing this here that you will understand that I am trying to act in good faith by being honest about how it was used, I am not here to make arguments for or against LLM assistance.

I am not interested in being a shill for AI, if you are looking to promote this project on your AI-centric Twitter page or blog, please leave me alone, I am not interested in being a hypebeast.
