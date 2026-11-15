// collector.c: load collector.bpf.c, scope it to two cgroups, write every ring
// record verbatim to OUTDIR/events.bin, and on SIGINT/SIGTERM detach, drain and
// write OUTDIR/counters.json (the loss proof).
// usage: collector OUTDIR FOCUS_CGROUP_DIR OTHER_CGROUP_DIR
// Records are tagged scope 1 (under FOCUS) or 2 (under OTHER, e.g. the cgroup root = everything else).
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/types.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "collector.h"
#include "collector.skel.h"

#define MAXCPU 1024
static volatile sig_atomic_t stop;
static FILE *out;
static __u64 received[MAXCPU], next_seq[MAXCPU], gaps, reorder, bytes;

static void on_signal(int sig) { (void)sig; stop = 1; }

static int on_record(void *ctx, void *data, size_t size)
{
	(void)ctx;
	struct hdr *h = data;
	if (h->cpu >= MAXCPU || h->size != size) { fprintf(stderr, "bad record\n"); exit(1); }
	if (h->seq > next_seq[h->cpu]) gaps += h->seq - next_seq[h->cpu];
	if (h->seq < next_seq[h->cpu]) reorder++;
	else next_seq[h->cpu] = h->seq + 1;
	received[h->cpu]++;
	bytes += size;
	if (fwrite(data, size, 1, out) != 1) { perror("write"); exit(1); }
	return 0;
}

int main(int argc, char **argv)
{
	if (argc != 4) { fprintf(stderr, "usage: %s OUTDIR FOCUS_CGROUP OTHER_CGROUP\n", argv[0]); return 2; }
	char path[4096];
	int ncpu = libbpf_num_possible_cpus();
	if (ncpu <= 0 || ncpu > MAXCPU) return 1;

	struct collector_bpf *skel = collector_bpf__open();
	if (!skel) return 1;
	bpf_map__set_max_entries(skel->maps.scratch, ncpu);
	bpf_map__set_max_entries(skel->maps.rb, 1u << 30);   /* 1 GiB ring */
	skel->rodata->self_tgid = getpid();
	if (collector_bpf__load(skel)) { fprintf(stderr, "load failed\n"); return 1; }
	for (__u32 i = 0; i < 2; i++) {
		int fd = open(argv[2 + i], O_RDONLY | O_DIRECTORY);
		if (fd < 0 || bpf_map_update_elem(bpf_map__fd(skel->maps.scopes), &i, &fd, BPF_ANY)) { perror(argv[2 + i]); return 1; }
	}
	snprintf(path, sizeof(path), "%s/events.bin", argv[1]);
	if (!(out = fopen(path, "w"))) { perror(path); return 1; }
	setvbuf(out, NULL, _IOFBF, 8 << 20);
	struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), on_record, NULL, NULL);
	if (!rb) return 1;
	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);
	if (collector_bpf__attach(skel)) { fprintf(stderr, "attach failed\n"); return 1; }
	fprintf(stderr, "collector: recording\n");

	struct timespec idle = { 0, 5 * 1000 * 1000 }; /* records are written with NO_WAKEUP; poll every 5 ms */
	while (!stop) {
		int n = ring_buffer__consume(rb);
		if (n < 0 && n != -EINTR) { fprintf(stderr, "consume: %d\n", n); return 1; }
		if (n == 0) nanosleep(&idle, NULL);
	}
	collector_bpf__detach(skel);   /* no new records after this */
	while (ring_buffer__consume(rb) > 0) ;
	fclose(out);

	/* Loss proof. */
	__u64 c[NCOUNTERS] = {0}, v[MAXCPU];
	for (__u32 k = 0; k < NCOUNTERS; k++) {
		if (bpf_map_lookup_elem(bpf_map__fd(skel->maps.counters), &k, v)) return 1;
		for (int i = 0; i < ncpu; i++) c[k] += v[i];
	}
	__u64 total = 0, misses = 0;
	for (int i = 0; i < ncpu; i++) total += received[i];
	snprintf(path, sizeof(path), "%s/counters.json", argv[1]);
	FILE *f = fopen(path, "w");
	if (!f) return 1;
	fprintf(f, "{\n  \"seen\": %llu, \"emitted\": %llu, \"emit_fail\": %llu, \"busy_skip\": %llu,\n"
		   "  \"received\": %llu, \"seq_gaps\": %llu, \"seq_reorder\": %llu, \"bytes\": %llu,\n"
		   "  \"truncated_fields\": %llu, \"user_read_faults\": %llu, \"faults_refetched_at_exit\": %llu,\n  \"programs\": {",
		(unsigned long long)c[C_SEEN], (unsigned long long)c[C_OK], (unsigned long long)c[C_FAIL],
		(unsigned long long)c[C_BUSY], (unsigned long long)total, (unsigned long long)gaps,
		(unsigned long long)reorder, (unsigned long long)bytes, (unsigned long long)c[C_TRUNC],
		(unsigned long long)c[C_FAULT], (unsigned long long)c[C_REFETCHED]);
	struct bpf_program *p;
	const char *sep = "";
	bpf_object__for_each_program(p, skel->obj) {
		struct bpf_prog_info info = {};
		__u32 len = sizeof(info);
		bpf_prog_get_info_by_fd(bpf_program__fd(p), &info, &len);
		misses += info.recursion_misses;
		fprintf(f, "%s\n    \"%s\": {\"run_cnt\": %llu, \"run_time_ns\": %llu, \"recursion_misses\": %llu}", sep,
			bpf_program__name(p), (unsigned long long)info.run_cnt, (unsigned long long)info.run_time_ns,
			(unsigned long long)info.recursion_misses);
		sep = ",";
	}
	int lossless = c[C_SEEN] == c[C_OK] && c[C_FAIL] == 0 && c[C_BUSY] == 0 && c[C_OK] == total && gaps == 0 && reorder == 0 && misses == 0;
	fprintf(f, "\n  },\n  \"lossless\": %s\n}\n", lossless ? "true" : "false");
	fclose(f);
	fprintf(stderr, "collector: %llu records, lossless=%d\n", (unsigned long long)total, lossless);
	return lossless ? 0 : 3;
}
