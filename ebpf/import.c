#include <linux/mm_types.h>
#include <linux/sched.h>
#include <net/sock.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <linux/nsproxy.h>     
#include <linux/pid_namespace.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/pkt_cls.h>
#define IP_TCP 6
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

struct label_header {
    char label[7];
};

struct key_type {
    char src[7];
    char dst[7];
};

struct event_xdp {
    char source_label[7];
    char container_name[7];
    u32 decision;
};

BPF_PERF_OUTPUT(events_xdp);
BPF_HASH(access_control, struct key_type, u32);