ARCH_INCLUDE ?= /usr/include/x86_64-linux-gnu

collector: collector.c collector.h collector.skel.h
	$(CC) -O2 -Wall -o $@ collector.c -lbpf

collector.skel.h: collector.bpf.o
	bpftool gen skeleton $< > $@

collector.bpf.o: collector.bpf.c collector.h vmlinux.h
	clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I$(ARCH_INCLUDE) -c $< -o $@

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

syscalls.tsv:
	awk '/^#define __NR_/ {sub("__NR_", "", $$2); print $$3 "\t" $$2}' $(ARCH_INCLUDE)/asm/unistd_64.h > $@

clean:
	rm -f collector collector.skel.h collector.bpf.o vmlinux.h syscalls.tsv
