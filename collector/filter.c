// filter.c: keep only records with the given scope (1 = S_FOCUS, 2 = S_OTHER)
// from a collector events.bin on stdin, to stdout. Records are self-delimiting
// (hdr.size); the loss proof stays in counters.json, which counts all records.
// usage: filter <scope> < events.bin > events-focus.bin
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    if (argc != 2) { fprintf(stderr, "usage: %s SCOPE < events.bin\n", argv[0]); return 2; }
    unsigned char want = (unsigned char)strtoul(argv[1], NULL, 0);
    unsigned char hdr[8];
    unsigned long long in = 0, out = 0;
    unsigned char buf[1 << 16];

    while (fread(hdr, 1, 8, stdin) == 8) {
        unsigned int size;
        memcpy(&size, hdr, 4);
        unsigned char scope = hdr[6];
        if (size < 8) { fprintf(stderr, "bad size %u at record %llu\n", size, in); return 1; }
        in++;
        unsigned int rest = size - 8;
        unsigned char keep = scope == want;
        if (keep)
            fwrite(hdr, 1, 8, stdout);
        while (rest) {
            size_t n = fread(buf, 1, rest > sizeof(buf) ? sizeof(buf) : rest, stdin);
            if (!n) { fprintf(stderr, "truncated record %llu\n", in); return 1; }
            if (keep)
                fwrite(buf, 1, n, stdout);
            rest -= n;
        }
        if (keep)
            out++;
    }
    fprintf(stderr, "filter: %llu in, %llu out\n", in, out);
    return 0;
}
