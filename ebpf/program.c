#include <stdint.h>

#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>

SEC("tc")
int hook(struct __sk_buff* skb) {
    char message[] = "Got a Packet!\n";
    bpf_trace_printk(message, sizeof message);

    return 0;
}

char _license[] SEC("license") = "GPL";
