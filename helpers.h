/*
 * =====================================================================================
 *
 *       Filename:  helpers.h
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  07/01/2020 01:08:32 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */


struct key_v4
{
u32 prefixlen;
u32 ip;
};

static void swap_src_dst_mac(void *data)
{
    unsigned short *p = data;
    unsigned short dst[3];

    dst[0] = p[0];
    dst[1] = p[1];
    dst[2] = p[2];
    p[0] = p[3];
    p[1] = p[4];
    p[2] = p[5];
    p[3] = dst[0];
    p[4] = dst[1];
    p[5] = dst[2];
}

static int carry(u32 csum) {
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16); // loop
    return ~csum;
}
static int sum16_32(u32 v) {
    return (v >> 16) + (v & 0xffff);
}

static int sum16(const void* data, u32 size, const void* data_end) {
    u32 s = 0;
#pragma unroll
    for (u32 i = 0; i < MAX_CSUM_WORDS; i++) {
        if (2*i >= size) {
            return s; /* normal exit */
        }
        if (data + 2*i + 1 + 1 > data_end) {
            return 0; /* should be unreachable */
        }
        s += ((const u16*)data)[i];
    }
    return s;
}

static inline unsigned short checksum(unsigned short *buf, int bufsz) {
    unsigned long sum = 0;
    while (bufsz > 1) {
        sum += *buf;
        buf++;
        bufsz -= 2;
    }
    if (bufsz == 1) {
        sum += *(unsigned char *)buf;
    }
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    return ~sum;
}

static int cookie_calculation (struct iphdr *iph, struct tcphdr *tcph)
{
u32 ports_for_hashing = tcph->source<<16;
ports_for_hashing = ports_for_hashing + tcph->dest;
u64 ts = bpf_ktime_get_ns() /1000000000; //Timestamp is in nanoseconds and we use a level of seconds (one second) to evaluate the reponse, if benign packet spends more than 1 sec to send a response, the source IP cannot be validated
u32 cookie = __jhash_nwords(iph->saddr,iph->daddr,ports_for_hashing,0);
return cookie;
}

static int syn_cookie_mitigation (void *data, void *data_end,struct iphdr *iph,struct tcphdr *tcph)
{
u8 action = XDP_DROP;
       
       if (tcph->syn ==1 && tcph->ack != 1)
           {
       u32 cookie = cookie_calculation(iph,tcph);
       tcph->ack_seq = bpf_htonl(bpf_ntohl(tcph->seq) + 1);
       tcph->seq = bpf_htonl(cookie);
       tcph->ack = 1;
           action = XDP_TX;
       }
       else if (tcph->syn !=1 & tcph->ack == 1)
       {
       u32 cookie = cookie_calculation(iph,tcph);
           if (bpf_htonl(tcph->ack_seq) == cookie+1)
                        {
                        action = 32;
                        //u64 ts = bpf_ktime_get_ns() /1000000000 ;
                        //trie.insert(&iph->saddr,&ts);
                        tcph->ack_seq = bpf_htonl(bpf_ntohl(tcph->seq) + 1);
                        tcph->ack = 0;
                        tcph->rst = 1;
                        }
       }
       else
       {
       // if packet is not syn or ack drop
       return XDP_DROP;
       }
       // mac swap
       swap_src_dst_mac(data);
       //ip swap
       __be32 temp_ip = iph->daddr;
       iph->daddr = iph->saddr;
       iph->saddr = temp_ip;
       // ip checksum calculation
       iph->check = 0;
       iph->check = checksum((unsigned short *)iph, sizeof(struct iphdr));
       // port swap
       u16 temp_port = tcph->dest;
       tcph->dest = tcph->source;
       tcph->source = temp_port;
       //tcp checksum calculation
       unsigned short tcp_len = ntohs(iph->tot_len) - (iph->ihl<<2);
       u32 tcp_csum = 0;
       tcp_csum += sum16_32(iph->saddr);
       tcp_csum += sum16_32(iph->daddr);
       tcp_csum += 0x0600; 
       tcp_csum += tcp_len << 8;
       tcph->check = 0;
       tcp_csum += sum16(tcph, tcp_len, data_end);
       tcph->check = carry(tcp_csum);
       return action;
}
