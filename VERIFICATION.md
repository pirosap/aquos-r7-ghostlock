# AQUOS R7 GhostLock verification

Verified on 2026-09-20 against an AQUOS R7 (`Mineva`, SGA202SH/A202SH)
running Android 14 build 03.00.06 and kernel
`5.10.218-android12-9-00041-g124993efd06e-ab12385094` (SM8450, LTO_FULL,
SELinux enforcing at boot, `perf_event_paranoid=-1`).

## Result

With the option set `--use-setattr --stamp3 --perm-pc --cred-swap
--install-su --stamp-off 0xf0`, the exploit completed the dangling-waiter
setup, settled the waiter into a zero-BSS fake mutex, flipped SELinux from
enforcing to permissive, set UID to 0, and started the built-in `su`
command daemon.

Representative exploit output (release binary, fresh boot):

```text
[*] _text=ffffffd693000000 slide=000000168b000000 data_delta=0
[*] selinux_state=ffffffd695a41b98 fake_lock=ffffffd69598ab88 ...
[+] dangling waiter armed (y_tid=8925)
[*] first-touch write_trigger=1 enforce=1->0
[+] SELinux permissive verified
[+] ROOT + permissive verified
[+] su daemon on 127.0.0.1:9999 (su=/data/local/tmp/su)
```

Independent readback through the `su` client:

```text
uid=0(root) gid=2000(shell) groups=2000(shell) context=u:r:kernel:s0
Permissive
```

This is real UID 0 plus SELinux permissive. It is not full capability root
(the inherited Android shell bounding set remains restricted), the SELinux
context stays `u:r:kernel:s0`, and a reboot returns the device to its
normal state. Do not kill the parked exploit processes while using `su`.

## First run of a boot: 10/10

A scripted campaign rebooted the device ten times and ran the exploit once
per boot, with the delay after `sys.boot_completed` shuffled across
30/60/90/120/150/180/210/240/270/300 s. Result (delay in s, seconds until
root confirmed):

```text
delay_s  result  root_ok_s          delay_s  result  root_ok_s
   30    ROOT        5                 180   ROOT        5
   60    ROOT        5                 210   ROOT        5
   90    ROOT        6                 240   ROOT        5
  120    ROOT        5                 270   ROOT        5
  150    ROOT        5                 300   ROOT        5
```

10/10 success, zero panics. The success of the first run of a boot did not
depend on the run timing.

## Second run of a boot: kernel panic

Running the exploit a second time while a first-run root session was still
alive (parked exploit process plus daemon) triggered a kernel panic within
~15 s; the device recovered automatically in ~41 s. This is consistent with
the intermittent panics seen during development when the exploit was
re-run inside an already-exploited kernel, and motivates the
one-run-per-boot rule in [README.md](README.md).

## Stripped release binary: 3/3

The release asset is the `llvm-strip`-ed build (598,672 bytes; SHA-256
`d3056b65…`). Three fresh-boot trials using that exact file (device-side
md5 `7fcf5e6e7266e538ccf92cbaf2ea5f72`), executed 30 s after boot
completion, reached UID 0 with SELinux permissive 3/3 (5–6 s each).

## Build reproducibility

`src/ghostlock510.c` built with Android NDK r30 clang
(`--target=aarch64-linux-android29 -O2 -Wall -Wextra -Werror -static
-pthread`) is byte-identical (MD5 `fa896ebd361519766b46cc2bab70dea2`) to
the unstripped binary used in every on-device test above.

## R7 calibration

Authority for all kernel offsets: the kernel actually running on the device
was proven byte-identical to Android CI kernel build **12385094** (raw
`Image` extracted from the device `boot_a`, re-embedded as an ELF R-segment
at its VA-aligned offset, compared against that build's `vmlinux`).

Key deltas found while porting from the R6 (5.4 + ThinLTO) calibration,
each disassembly-verified — several invalidate the R6 assumptions outright:

- KASLR: the slide is 2 MB-aligned and `_text` links at a 2 MB boundary, so
  aligning the minimum leaked IP down to 2 MB **is** runtime `_text` (no R6
  `+0x80000` adjustment).
- `selinux_state` leak: the usable x8 window inside `sel_read_enforce` is
  `+0x28..+0x3c` (R6: `+0x58..+0x60`), and the true pointer is not 4 KB
  aligned, so the R6 page-alignment filter would reject it.
- `task_state`: the task argument persists in x25 and cred in x23
  (different registers than R6).
- Zero-BSS scratch: the only BSS zero run ≥ 0x400 bytes is
  `__bss_start+0x1188..+0x2000` (0xe78 bytes); the fake task, fake lock and
  write windows all live there.
- `selinux_state.enforcing` is at struct offset 0 on this build (R6 wrote
  offset 1).
- `task_struct` credential offsets on this build: `real_cred=+0x778`,
  `cred=+0x780`.

Stack geometry (waiter at syscall-entry SP−0x198, FPSIMD copy at
SP−0x2e0, stamp in `fpsimd_context.vregs` at +0x148, length 0x50) was
carried over from R6 and confirmed by on-device success; 5.10 full-LTO
frames are not 5.4 ThinLTO frames, so treat it as validated for this build
only.

`tools/r7probe.c` is the read-only calibration probe (perf sampling plus
file reads — KASLR leak, kernel-IP histograms, raw sample dumps) that
established these values without writing to the kernel.

Known open item: the on-device `pstore` console capture of the panic
couldn't be read as shell (`/sys/fs/pstore` requires root), so the exact
panic backtrace of the second-run case is not yet archived.
