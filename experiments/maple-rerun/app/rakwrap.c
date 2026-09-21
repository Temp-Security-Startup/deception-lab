/* rakwrap.c — run an untrusted child under a rak-agent-shaped containment policy.
 *
 * rak-agent expresses containment as: exec allowlist, inode-keyed file rules, and a
 * network allowlist, compiled from a JSON policy by resources/rak_guard.py. In a full
 * deployment those rules are enforced by a BPF-LSM program in the kernel (see rak's
 * resources/guard.bpf.c + loader.c). BPF-LSM needs a staged VM (root + BPF LSM), which
 * this lab does not have, so this shim enforces the SAME POLICY SHAPE with Landlock,
 * a stacked LSM available unprivileged on Linux >= 5.13 (ABI >= 1; net rules ABI >= 4).
 *
 * It is an allowlist: once any file rule is added, every path not beneath an allowed
 * root is denied; once TCP is handled and no endpoint is added, all connect/bind is
 * denied. That is exactly the property that stops the estate chain: the decoder may
 * still be hijacked (the memory bug is untouched), but it can no longer read the
 * session secret or reach the IdP.
 *
 *   RAK_ALLOW=/usr:/bin:/lib:/lib64:/path/to/run   (colon-separated allow roots)
 *   RAK_NET=off|on                                 (default off)
 *   argv[1..] = command and args
 *
 * Build: cc -O2 -o rakwrap rakwrap.c
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/landlock.h>
#include <ctype.h>

#ifndef LANDLOCK_ACCESS_NET_BIND_TCP
#define LANDLOCK_ACCESS_NET_BIND_TCP   (1ULL << 0)
#define LANDLOCK_ACCESS_NET_CONNECT_TCP (1ULL << 1)
#endif

static int add_path(int rs, const char *path, uint64_t access) {
    int fd = open(path, O_PATH | O_CLOEXEC);
    if (fd < 0) return -1;
    struct landlock_path_beneath_attr pba = { .allowed_access = access, .parent_fd = fd };
    int r = syscall(__NR_landlock_add_rule, rs, LANDLOCK_RULE_PATH_BENEATH, &pba, 0);
    close(fd);
    return r;
}

static int add_net_port(int rs, int port, uint64_t access) {
    struct landlock_net_port_attr npa = { .allowed_access = access, .port = (uint64_t)port };
    return syscall(__NR_landlock_add_rule, rs, LANDLOCK_RULE_NET_PORT, &npa, 0);
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: rakwrap CMD [ARGS...]\n"); return 2; }
    const char *allow = getenv("RAK_ALLOW");
    const char *net = getenv("RAK_NET");
    int net_off = (net == NULL) || strcmp(net, "off") == 0;

    if (!allow) {  /* no policy -> exec directly (defense disabled) */
        execvp(argv[1], &argv[1]);
        perror("execvp"); return 127;
    }

    uint64_t fs = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR |
                  LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE;
    struct landlock_ruleset_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.handled_access_fs = fs;
    attr.handled_access_net = LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP;

    int abi = syscall(__NR_landlock_create_ruleset, NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 0) { perror("landlock ABI"); return 3; }
    int rs = syscall(__NR_landlock_create_ruleset, &attr, sizeof(attr), 0);
    if (rs < 0) {
        /* pre-ABI-4 kernel: retry without network handling */
        attr.handled_access_net = 0;
        rs = syscall(__NR_landlock_create_ruleset, &attr, sizeof(attr), 0);
        if (rs < 0) { perror("landlock_create_ruleset"); return 3; }
        net_off = 0;
    }

    char *spec = strdup(allow);
    for (char *p = strtok(spec, ":"); p; p = strtok(NULL, ":"))
        add_path(rs, p, fs);

    /* optional TCP allowlist: RAK_NET=allow with RAK_PORTS=18080,443. Landlock permits
     * connect_tcp only to the listed ports; everything else is denied. */
    int net_allow = (net != NULL) && strcmp(net, "allow") == 0;
    if (net_allow) {
        const char *ports = getenv("RAK_PORTS");
        char *pspec = strdup(ports ? ports : "");
        for (char *q = strtok(pspec, ",:"); q; q = strtok(NULL, ",:")) {
            int port = atoi(q);
            add_net_port(rs, port, LANDLOCK_ACCESS_NET_CONNECT_TCP);
            add_net_port(rs, port, LANDLOCK_ACCESS_NET_BIND_TCP);
        }
    }

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) { perror("no_new_privs"); return 4; }
    if (syscall(__NR_landlock_restrict_self, rs, 0) < 0) { perror("landlock_restrict_self"); return 4; }
    if (net_off) fprintf(stderr, "[rakwrap] contained: fs allowlist + TCP denied (abi=%d)\n", abi);
    else if (net_allow) fprintf(stderr, "[rakwrap] contained: fs allowlist + TCP allowlist %s (abi=%d)\n", getenv("RAK_PORTS") ? getenv("RAK_PORTS") : "", abi);
    else fprintf(stderr, "[rakwrap] contained: fs allowlist (abi=%d, net=%s)\n", abi, net_off ? "off" : "on");

    execvp(argv[1], &argv[1]);
    perror("execvp");
    return 127;
}