# AQUOS R7 GhostLock temporary root

Device-specific Linux 5.10 port of GhostLock (CVE-2026-43499) for the Sharp
AQUOS R7. The validated target is the AQUOS R7 (`Mineva`, SGA202SH/A202SH)
running Android 14 build `03.00.11`, kernel
`5.10.237-android12-9-00013-gd09ef2e980e0-ab13968955` (SM8450).
The previous validated target, build `03.00.06` / kernel
`5.10.218-android12-9-00041-g124993efd06e-ab12385094`, is preserved in
git tag `v1.0-030006`.

This is a port of [aquos-r6-ghostlock](https://github.com/mouseos/aquos-r6-ghostlock)
(AQUOS R6, kernel 5.4.61-qgki). Every constant — KASLR handling, the
`selinux_state` leak window, task/cred offsets, the zero-BSS scratch region —
was re-derived and validated against the R7 kernel; the R6 stack geometry
served only as a starting reference.

A successful run gives you UID 0 with SELinux permissive and starts a small
`su` command daemon. It does not grant a full Linux capability set and the
change is not persistent: a reboot restores the stock kernel state.

## Build

The Android NDK clang targeting `aarch64-linux-android29` is required (tested
with NDK r30):

```sh
make build/ghostlock510   # ~3.4 MB static binary
make strip                # optional; ~0.6 MB, same behaviour
```

Reproducibility (03.00.11 calibration): this source, built with the toolchain
above, is byte-identical (MD5 `25fc1d5d0e92d36c56f00f983a49667d`) to the
binary used in the on-device 03.00.11 test. The release asset is the
`llvm-strip`-ed form of exactly that binary (598,672 bytes, SHA-256
`5c413a80e9fcc41032412f4e0e5183bc723dde9a2e0ace5a6d9c79681b04b9cd`).
For the 03.00.06 build see tag `v1.0-030006` (unstripped MD5
`fa896ebd361519766b46cc2bab70dea2`).

## Run

Push the binary (release asset or your own build) and run it **once**:

```sh
adb push ghostlock510 /data/local/tmp/ghostlock510
adb shell chmod 755 /data/local/tmp/ghostlock510
adb shell "setsid nohup /data/local/tmp/ghostlock510 --use-setattr --stamp3 --perm-pc --cred-swap --install-su --stamp-off 0xf0 --log /data/local/tmp/ghostlock510.log </dev/null >/dev/null 2>&1 &"
```

Use the installed `su` client for root commands (full path required):

```sh
adb shell "/data/local/tmp/su -c 'id; getenforce'"
# uid=0(root) gid=2000(shell) groups=2000(shell) context=u:r:kernel:s0
# Permissive
```

`su` talks to the exploit's daemon over loopback TCP (port 9999); no
persistent root shell is attached. Commands are line-based, and nesting `su`
inside `su` does not work. Interactive programs (vi, top, …) want a PTY; an
interactive `su` mode on top of the daemon is left as future work.

## One exploit run per boot

Measured on this exact build (see [VERIFICATION.md](VERIFICATION.md)):

- The **first** run after a clean boot succeeded 10/10 times, independent of
  when it was executed (30–300 s after boot completion).
- A **second** run while a root session was still alive triggered a kernel
  panic within seconds. The device recovers automatically (~40–90 s).

So: reboot, run `ghostlock510` once, and do not run it again while that
session lives. Reboot is the cleanup path.

## Important safety notes

- Calibrated for the exact device/build above. Do not run it on other kernels
  without independently validating every offset and stack geometry.
- After a successful run, kernel PI references point into a live worker
  thread's stack. Do not kill the parked exploit process(es).
- Use only on hardware you own or are explicitly authorized to test.

## Calibration provenance

Large external inputs are deliberately not included in this repository:

- 03.00.11: kernel offsets and disassembly were taken from the
  `vmlinux`/System.map of Android CI kernel build **13968955**; byte-level
  identity with the kernel actually running on the device was verified via
  its `boot_b` image (all 23 PT_LOAD segments, per-segment compare).
  The CVE fix (5.10.y backport 2026-07-21) post-dates this tree
  (HEAD 2025-08-20), and `kernel/futex/core.c` is blob-identical to the
  03.00.06 build — the vulnerability is still present.
- 03.00.06 (tag `v1.0-030006`): offsets came from Android CI kernel build
  **12385094**, byte-verified via the device `boot_a` image.
- SHARP OSS firmware **03.00.01** was used as the device source reference.

## References

- [mouseos/aquos-r6-ghostlock](https://github.com/mouseos/aquos-r6-ghostlock)
  — the direct porting source (AQUOS R6, Apache-2.0).
- [R0rt1z2/GhostLock](https://github.com/R0rt1z2/GhostLock) — the upstream
  5.10-series PoC (Amazon devices); the `--stamp3` / `--use-setattr` approach
  was inspired by it (no license stated in that repository).

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
