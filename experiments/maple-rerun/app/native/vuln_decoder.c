/* vuln_decoder.c — a REAL, deliberately-vulnerable native image decoder.
 *
 * This is a small program I wrote; it is NOT libheif. But the bug is the real
 * thing: a HEIF-ish 'grid' box carries a length field the decoder trusts and
 * memcpy()s into a fixed buffer, so an oversized box overflows it and overwrites
 * an adjacent function pointer the decoder later calls — a genuine control-flow
 * hijack via memory corruption, mirroring libheif's overlay/grid overlap-area bug.
 *
 * Toggles (all real):
 *   -DVPATCH   compiles an in-decoder bounds check that rejects the oversized box
 *              BEFORE the copy — the "in-process virtual patch". The overflow can
 *              no longer happen.
 *   env SECCOMP=1  installs a real seccomp-bpf filter that KILLs the process if it
 *              reaches execve — so even a successful hijack cannot spawn a shell.
 *
 * Build:
 *   gcc -no-pie -fno-stack-protector -O0 -o vuln_decoder vuln_decoder.c -lseccomp
 * -no-pie fixes win()'s address so the exploit is deterministic without any ASLR
 * bypass; -fno-stack-protector leaves the classic overflow intact.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <seccomp.h>

extern char **environ;

struct decoder {
    char canvas[64];                    /* fixed decode buffer                 */
    void (*on_decoded)(struct decoder*);/* function pointer, adjacent in memory*/
    char cmd[512];                      /* lands here after the pointer        */
};

/* The benign default callback. */
static void finalize_ok(struct decoder *d) {
    (void)d;
    fprintf(stderr, "[decoder] image decoded OK via finalize_ok() (benign path)\n");
}

/* The gadget the attacker redirects control to. In a real exploit this is
 * shellcode / a ROP chain; here it is a real function whose real address the
 * crafted image writes into the corrupted pointer, and it really execve()s. */
void win(struct decoder *d) {
    fprintf(stderr, "[decoder] *** CONTROL-FLOW HIJACKED -> win() *** exec attacker cmd\n");
    char *argv[] = {"/bin/sh", "-c", d->cmd, NULL};
    execve("/bin/sh", argv, environ);
    /* Reached only if execve was blocked by seccomp before the kernel killed us. */
    perror("[decoder] execve");
    _exit(3);
}

static void maybe_seccomp(void) {
    const char *s = getenv("SECCOMP");
    if (!s || strcmp(s, "1") != 0) return;   /* only when explicitly enabled */
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);      /* allow-by-default */
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(execve), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(execveat), 0);
    if (seccomp_load(ctx) == 0)
        fprintf(stderr, "[decoder] seccomp loaded: execve -> SIGSYS/KILL\n");
    seccomp_release(ctx);
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <image>\n", argv[0]); return 1; }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("open"); return 1; }

    unsigned char magic[4] = {0};
    if (fread(magic, 1, 4, f) != 4 || memcmp(magic, "HEIF", 4)) {
        fprintf(stderr, "[decoder] not a HEIF file\n"); fclose(f); return 1;
    }

    struct decoder d;
    memset(&d, 0, sizeof d);
    d.on_decoded = finalize_ok;         /* default, benign */

    maybe_seccomp();

    /* Walk boxes: [4-byte type][4-byte little-endian length][length bytes]. */
    for (;;) {
        unsigned char bh[8];
        if (fread(bh, 1, 8, f) != 8) break;
        char type[5] = {0};
        memcpy(type, bh, 4);
        uint32_t len = bh[4] | (bh[5] << 8) | (bh[6] << 16) | ((uint32_t)bh[7] << 24);
        fprintf(stderr, "[decoder] box '%s' len=%u\n", type, len);

        unsigned char *data = malloc(len ? len : 1);
        if (!data || fread(data, 1, len, f) != len) { free(data); break; }

        if (!strcmp(type, "grid")) {
#ifdef VPATCH
            if (len > sizeof(d.canvas)) {
                fprintf(stderr, "[decoder] VPATCH: grid len=%u > canvas=%zu -> REJECT "
                                "(overflow neutralized at the sink)\n", len, sizeof(d.canvas));
                free(data); fclose(f); return 2;
            }
#endif
            /* THE VULNERABILITY: length is attacker-controlled and untrusted. */
            memcpy(d.canvas, data, len);
        }
        free(data);
    }
    fclose(f);

    /* Benign -> finalize_ok. If the pointer was overwritten -> win(). */
    d.on_decoded(&d);
    return 0;
}
