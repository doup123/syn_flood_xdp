#!/usr/bin/env python
#
# xdp_drop_count.py Drop incoming packets on XDP layer and count for which
#                   protocol type
#
# Copyright (c) 2016 PLUMgrid
# Copyright (c) 2016 Jan Ruth
# Licensed under the Apache License, Version 2.0 (the "License")

from bcc import BPF
import pyroute2
import time
import sys
import ctypes as ct
import socket
import struct
import ipaddress
import binascii
import pandas as pd


def reverser(ipa):
    import ipaddress
    ip_splitted = ipaddress.IPv4Address(ipa).__str__().split(".")
    ip_reversed = '.'.join(list(reversed(ip_splitted)))

def set_ip_to_blacklist(ip,bpf_map):
    ip_splitted = ip.split(".")
    ip_reversed = '.'.join(list(reversed(ip_splitted)))
    ip_hex = binascii.hexlify(socket.inet_aton(ip_reversed))
    bpf_map.__setitem__(ct.c_int32(int(ip_hex,16)),ct.c_long(1))
    return True

def create_tcp_signatures(bpf_table,df):
    df = df.dropna()[["ip.ttl","tcp.window_size_value"]].drop_duplicates()
    for i in range(0,len(df)):
	 tcp_signatures_key = bpf_table.Key()
	 tcp_signatures_key.ttl = int(df.iloc[i]["ip.ttl"])
	 tcp_signatures_key.window = int(df.iloc[i]["tcp.window_size_value"])
	 bpf_table.__setitem__(tcp_signatures_key,ct.c_long(1))

def bpf_logic(bpf_program):
    #trie = bpf_program.get_table("trie")
    tcp_signatures_map = bpf_program.get_table("signatures")
    #start = time.time()
    #for i in drop_list:
    #    set_ip_to_blacklist(i,trie)
    #end = time.time()
    #print('blacklist loaded: {} seconds'.format(end - start))
    count = 0
    while 1:
        count = count + 1
        try:
            if count==1:
                #pass
                create_tcp_signatures(tcp_signatures_map,pd.read_csv("/mnt/journal1/ip_stresser_com/tcp_syn_ddos/tcp_syn_ip_stresser_highly_distributed.pcap.tcp_syn_packet_fields.csv").drop_duplicates())
            print('Timewindow {}'.format(count))
            for elem in tcp_signatures_map.keys():
                print(elem.ttl,elem.window,tcp_signatures_map[elem].value)
                #if count==15:
                #    trie.__delitem__(elem)
                #    print("Key Deleted: "+str(elem))
            
            time.sleep(5)

        except KeyboardInterrupt:
            print("Removing filter from device")
            break


def main(args):
    flags = 0

    if len(sys.argv) == 2:
        device = sys.argv[1]

    elif len(sys.argv) == 3:
        if "-S" in sys.argv:
            # XDP_FLAGS_SKB_MODE
            flags |= 2 << 0

        if "-S" == sys.argv[1]:
            device = sys.argv[2]
        else:
            device = sys.argv[1]

    else:
        print("Usage: {0} [-S] <ifdev>".format(sys.argv[0]))
        print("       -S: use skb mode\n")
        print("e.g.: {0} eth0\n".format(sys.argv[0]))
        return 1

    mode = BPF.XDP
    #mode = BPF.SCHED_CLS

    if mode == BPF.XDP:
        ret = "XDP_DROP"
        ctxtype = "xdp_md"
    else:
        ret = "TC_ACT_SHOT"
        ctxtype = "__sk_buff"

    # load BPF program
    with open('syn_flood_mitigator_ml.c') as f:
        lines = f.read()

    # load BPF program
    b = BPF(text=lines, cflags=["-w"], debug=0)

    fn = b.load_func("xdp_program", mode)

    if mode == BPF.XDP:
        print("BPF_XDP")
        b.attach_xdp(device, fn, flags)

        bpf_logic(b)

    else:
        ip = pyroute2.IPRoute()
        ipdb = pyroute2.IPDB(nl=ip)
        idx = ipdb.interfaces[device].index
        ip.tc("add", "clsact", idx)
        ip.tc("add-filter", "bpf", idx, ":1", fd=fn.fd, name=fn.name,
              parent="ffff:fff2", classid=1, direct_action=True)

    if mode == BPF.XDP:
        b.remove_xdp(device, flags)
    else:
        ip.tc("del", "clsact", idx)
        ipdb.release()


if __name__ == "__main__":
    main(sys.argv)
