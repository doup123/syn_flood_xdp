#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/in.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/tcp.h>
#include <bcc/proto.h>
#include<uapi/linux/string.h>
#define ETH_LEN 14
#define MAX_CSUM_WORDS 32
#define INTERNAL static __attribute__((always_inline))
#include <jhash.h>
#include "helpers.h"

struct tcp_signature
{
u32 window;
u32 ttl;
};

BPF_HASH(trie, u32, u64,1000000);
BPF_HASH(signatures, struct tcp_signature , u32,100);
//BPF_HASH(dns_counter,struct key,u64,1000000);
//BPF_HASH(dns_dropper,struct key,u64,1000000);
//BPF_HASH(dropcnt,u32,u64,1000);


int  xdp_program(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	uint64_t nh_off = sizeof(*eth);
	u8 action = XDP_DROP;

	if (data + nh_off > data_end) {
		return XDP_PASS;
	}
	uint16_t h_proto = eth->h_proto;
	int i;
	//bpf_trace_printk("data: %d,data_end %d",ctx->data,ctx->data_end); //Packet Length
        u16 packet_size = ctx->data_end - ctx->data;
	if (h_proto == htons(ETH_P_IP)) {
		struct iphdr *iph = data + nh_off;
		struct tcphdr *tcph = data + nh_off + sizeof(struct iphdr);

		if (tcph + 1 > (struct tcphdr *)data_end) {
			return XDP_PASS;
		}
		if (iph->protocol == IPPROTO_TCP)
       {
           //TCP Signatures
           struct tcp_signature tcp_sign;
           tcp_sign.ttl = iph->ttl;
           tcp_sign.window = htons(tcph->window);
	   //u64 start = bpf_ktime_get_ns();
           u32 *existing_signature = signatures.lookup(&tcp_sign);
           if (existing_signature) return XDP_DROP;

           //bpf_trace_printk("TTL: %d , Window: %d",iph->ttl,htons(tcph->window));
	   u64 value = trie.lookup(&iph->saddr);
           //u64 start = bpf_ktime_get_ns();
           //bpf_trace_printk("Lookup_Time %lld \n",stop-start);
	   // BPF HASH MAP  
	   //u64 value = trie.lookup(&iph->saddr);
	   //bpf_trace_printk("iph->saddr: %d", trie_key.ip);
	   if (value)
			{
			//bpf_trace_printk("IP Whitelisted");
			return XDP_PASS;
			}
          
           action = syn_cookie_mitigation(data,data_end,iph,tcph);
           // This is a hack for inserting ip address to the map
           if (action==32)
           {
           u64 ts = bpf_ktime_get_ns() /1000000000;
           // Here is the destination address since it is swapped in the syn_cookie mitigation function
           trie.insert(&iph->daddr,&ts);
           action = XDP_TX;  
           return action;	
	   }
} 
	return action;
}
}
