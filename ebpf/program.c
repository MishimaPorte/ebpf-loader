#include <stdint.h>

#include <linux/bpf.h>
#include <linux/pkt_cls.h>

#include <bpf/bpf_helpers.h>

__attribute__((noinline))
 // __attribute__((section("sec2")))
void print_thing(int len) {
    bpf_printk("Got a Packet: length is %d!\n", len);
    return;
}

volatile int a = 100;

__attribute__((noinline))
 // __attribute__((section("sec1")))
void aboba() {
    bpf_printk("aboba\n");
    a = 101;
    return;
}

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, 16);
} icmpcnt SEC(".maps");

SEC("tc")
int hook(struct __sk_buff* skb) {
    print_thing(skb->len);
    aboba();

    int key = 0;
    int *value = bpf_map_lookup_elem(&icmpcnt, &key);
    bpf_printk("ok %d (%d): %d\n", a, *value, bpf_get_current_cgroup_id());

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
