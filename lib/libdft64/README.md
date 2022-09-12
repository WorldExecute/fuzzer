# libdft: Practical Dynamic Data Flow Tracking

These code is modified from [Angora](https://github.com/AngoraFuzzer/libdft64), and it is originally from [libdft](https://www.cs.columbia.edu/~vpk/research/libdft/).

We modify the `libdft64` to make it be more suitable for *MirageFuzz*. And some modifications are too tricky to give a PR to [Angora](https://github.com/AngoraFuzzer/libdft64).

# Modification
## Fix some defects
- Patch taint process for `mmap`
- Add missing `break` to `switch-case`.
## Modify original taint propation rules.
Modify taint propagtion rules for `movsx`.
## Support new instructions
Define taint propation rules for `movzx`, `bswap`, most shift instructions and etc.

