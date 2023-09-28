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
#include "hash_func01.h"
#include "helpers.h"

//BPF_LPM_TRIE(trie, struct key_v4, int, 255);
//BPF_LPM_TRIE(tre);
BPF_HASH(tcp_syn, u32, u64,1000000);
BPF_HASH(tcp_rst, u32, u64,1000000);
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
           //u64 start = bpf_ktime_get_ns();
	   u64 *value = tcp_syn.lookup(&iph->saddr);
	   if (value)
			{
           		u64 ts = bpf_ktime_get_ns();
           		tcp_syn.update(&iph->saddr,&ts);
			return XDP_PASS;
			}
           if (tcph->syn==1 || tcph->ack==1)
	   {
           action = syn_cookie_mitigation(data,data_end,iph,tcph);
	   }
           // This is a hack for inserting ip address to the map
           if (action==32)
           {
           u64 ts = bpf_ktime_get_ns();
           // Here is the destination address since it is swapped in the syn_cookie mitigation function
           tcp_syn.insert(&iph->daddr,&ts);
           action = XDP_TX;  
	   }
	   if (tcph->rst==1)
	   {

               u64 *timestamp = tcp_rst.lookup(&iph->daddr);

                if (!timestamp) {
                    // If no entry exists for RST packets, create one
                    u64 ts = bpf_ktime_get_ns();
                    tcp_rst.insert(&iph->daddr, &ts);
                } else {
                    u64 current_time = bpf_ktime_get_ns();
                    u64 last_time = *timestamp;
                    u64 time_diff = current_time - last_time;
		   //bpf_trace_printk("Current Time: %llu\n", current_time);
		   // bpf_trace_printk("Last Time: %llu\n", last_time);
		   // bpf_trace_printk("Time Diff: %llu\n", time_diff);
                    // Adjust this rate limit threshold as needed
                    if (time_diff >= 1000000000) { // e.g., time diff defines the packet rate 10^9/time_diff which is in nanoseconds
                        // Update the timestamp
		        tcp_rst.update(&iph->daddr, &current_time);	
                    }
		    else
		    {
		    action = XDP_DROP;
		    }
		}
	}
	   
	return action;
}
return action;
}
}
