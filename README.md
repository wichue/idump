测试
 ./idump --file=ens33.pcap --save=11.txt --json=../config/filter.json


 使用wireshark的过滤习惯
 frame.len==60
 frame.cap_len==60

 eth
 eth.dst
 eth.dst==00-0c-29-95-c3-db
 eth.dst==00:0c:29:95:c3:db
 eth.src==00:0c:29:95:c3:db
 eth.type==86dd	#16进制
 eth.type==0800	#16进制

 ip.hdr_len==20
 ip.version==4
 ip.tos!=0
 ip.len>=80
 ip.id==b625	#16进制
 ip.fragment==0
 ip.ttl==128
 ip.proto==17	#17(udp);6(tcp)
 ip.checksum==f0c3	#16进制
 ip.src_host==192.168.220.128
 ip.dst_host==192.168.220.2

 ipv6.version==6
 ipv6.plen>=400
 ipv6.nxt==17	#17(udp);6(tcp)
 ipv6.src_host==fe80::9d30:4261:73d0:119f
 ipv6.dst_host==ff02::fb

 tcp.hdr_len==20
 tcp.srcport>=10000
 tcp.dstport < 10000
 tcp.seq > 294723434
 tcp.ack < 294723434
 tcp.fin==1
 tcp.syn==1
 tcp.reset==1
 tcp.push==1
 tcp.ack_flag==1
 tcp.urg==1
 tcp.ece==1
 tcp.cwr==1
 tcp.windows_size==64240
 tcp.checksum==5de1
 tcp.urgent_pointer==0

 udp.srcport==58339
 udp.dstport==53
 udp.length==69
 udp.checksum==3a2b
