#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <stdint.h>
#include <endian.h>
#include <string.h>
#include "common.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} rb SEC(".maps");

struct header_pointers {
	struct ethhdr *eth;
	struct iphdr *iph;
	struct tcphdr *tcph;
	__u16 tcph_len;
};

static int detect_jdwp_protocol(struct xdp_md *ctx, struct header_pointers *hdr)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    const char *target_string = "JDWP-Handshake";
    const uint64_t jdwp_handshake_len = strlen(target_string);
    struct jdwp_data_t jdwp_data = {};
    char *tcp_data;
    uint16_t src_port, dst_port; 
    uint32_t seq;

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
    
    /* https://github.com/torvalds/linux/blob/master/include/uapi/linux/tcp.h */
    bpf_probe_read_kernel_str(&src_port, sizeof(src_port), &hdr->tcph->source);
    bpf_probe_read_kernel_str(&dst_port, sizeof(dst_port), &hdr->tcph->dest);
    bpf_probe_read_kernel_str(&seq, sizeof(seq), &hdr->tcph->seq);
    jdwp_data.src_port = be16toh(src_port);    
    jdwp_data.dst_port = be16toh(dst_port);  
    jdwp_data.seq = be32toh(seq);  
    bpf_printk("seq: %ld", jdwp_data.seq);

    // Successfully processing a TCP packet at this point 
    tcp_data = (char *)(hdr->tcph + 1);
    if ((void *)tcp_data + MAXTCPDATA > data_end) {
        return XDP_PASS;
    }
     
    if (bpf_probe_read_kernel_str(jdwp_data.data, MAXTCPDATA, (void *)tcp_data) < 0)
        return XDP_ABORTED;
    bpf_ringbuf_output(&rb, &jdwp_data, sizeof(struct jdwp_data_t), 0);

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
