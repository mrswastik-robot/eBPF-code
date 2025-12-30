#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>

// Map to store the port number to block (configurable from userspace)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u16);
} blocked_port SEC(".maps");

// Map to count dropped packets
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} drop_count SEC(".maps");

SEC("tc")
int drop_tcp_port(struct __sk_buff *skb)
{
    // getting raw pointers first
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    // Only process IPv4 packets
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return TC_ACT_OK;

    // Parse IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    // Only process TCP packets
    if (ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    // ip->ihl*4 gives IP header length in bytes
    struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
    if ((void *)(tcp + 1) > data_end)
        return TC_ACT_OK;

    // Look up the blocked port from userspace-configurable map
    __u32 key = 0;
    __u16 *port = bpf_map_lookup_elem(&blocked_port, &key);
    if (!port)
        return TC_ACT_OK;

    // if dest port matches the blocked port
    if (tcp->dest == __constant_htons(*port)) {
        // inc drop counter
        __u64 *count = bpf_map_lookup_elem(&drop_count, &key);
        if (count)
            __sync_fetch_and_add(count, 1);
        
        return TC_ACT_SHOT;  // dropping the packet
    }

    return TC_ACT_OK;  //else allow it
}

char _license[] SEC("license") = "GPL";
