#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <stdint.h>
#include <string.h>
#include "common.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024 /* 256 KB */);
} rb SEC(".maps");

struct header_pointers {
	struct ethhdr *eth;
	struct iphdr *iph;
	struct tcphdr *tcph;
	__u16 tcph_len;
};

/* Identifies IPv4 packets */
static int is_IPV4(struct header_pointers *hdr)
{
    // Is IPv4 packet? 
    return bpf_ntohs(hdr->eth->h_proto) == ETH_P_IP && hdr->iph->version == 4;
}

/* Identifies TCP packets */
static int is_TCP(struct iphdr *iph) 
{
    return iph->protocol == IPPROTO_TCP;
}

static int detect_jdwp_protocol(struct xdp_md *ctx, struct header_pointers *hdr)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    const char *target_string = "JDWP-Handshake";
    const uint64_t jdwp_handshake_len = strlen(target_string);
    char *tcp_data;
    
    hdr->eth = data;
    // Checking ethernet packet header boundaries 
    hdr->iph = (void *)hdr->eth + sizeof(*hdr->eth);
    if ((void *)hdr->iph + 1 > data_end)
	    return XDP_DROP;
    // We only want IPv4 packets 
    if (hdr->iph->version != 4)
        return XDP_DROP;
    // Checking IP header boundaries 
    if (hdr->iph->ihl * 4 < sizeof(*hdr->iph))
	    return XDP_DROP;
    // Checking TCP header boundaries 
    hdr->tcph = (void *)hdr->iph + hdr->iph->ihl * 4;
    if ((void *)hdr->tcph + 1 > data_end)
        return XDP_DROP;
    // Successfully processing a TCP packet at this point 
    tcp_data = (char *)(hdr->tcph + 1);
    if ((void *)tcp_data + MAXTCPDATA  > data_end) {
        return XDP_PASS;
    }
     
    struct tcp_data_t tcp_data_msg = {};
    __builtin_memcpy(tcp_data_msg.data, tcp_data, MAXTCPDATA);
    
    bpf_printk("[+] Copying TCP data..");
    bpf_ringbuf_output(&rb, &tcp_data_msg, sizeof(&tcp_data_msg), 0);
    bpf_printk("[+] Done!");

    return XDP_PASS;
}

/* Filter packet coming from JDWP-based debuggers
 * by dropping JDWP handshake.
*/
SEC("xdp")
int filter_jdwp_packets(struct xdp_md *ctx)
{
    struct header_pointers hdr = {};
    detect_jdwp_protocol(ctx, &hdr);
    return XDP_PASS;    
}

char _license[] SEC("license") = "GPL";

