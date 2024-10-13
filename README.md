简体中文 | [English](./README_en.md)

# 纯C++实现的pcap文件解析工具

[![](https://img.shields.io/badge/license-MIT-green.svg)](https://github.com/wichue/idump/blob/master/LICENSE)
[![](https://img.shields.io/badge/language-c++-red.svg)](https://en.cppreference.com/)
[![](https://img.shields.io/badge/platform-linux%20|%20windows-blue.svg)](https://github.com/wichue/idump)
## 初衷
在分析海量的pcap抓包数据时，如何快速找到感兴趣的报文是个头疼的事，特别是一些自定义的协议，哪一条是心跳哪一条是认证，只能按字节去看，还要熟记每种报文的协议结构，不熟悉协议就像看天书，效率低下；在linux/arm等平台使用tcpdump抓包后，通常要拷贝到有wireshark的环境中去看，比较麻烦；在做丢包分析时，感觉有丢包错包，但具体在哪里丢了总不能一条条看吧，要找出具体在哪里丢了错了，有凭有据。针对上述生产中的问题，开发了该工具，与大家共勉。
## 项目特点
- 纯C++实现，没有其他依赖，编译简单使用方便，支持linux、windows平台。
- 命令行终端执行，可以在linux、arm等不方便使用wirshark的环境使用。
- 自定义json过滤条件，可自定义任意私有协议过滤，不局限于wireshark等常规协议过滤。
- 比对模式支持按字节比较两个pcap文件，可设置过滤条件和每个报文的首部和尾部偏移，用于分析丢包、错包、乱包等。
- 支持常用的常规协议过滤，过滤命令类似wireshark。

## 编译和安装
### linux
```shell
git clone git@github.com:wichue/idump.git
cd idump
mkdir build
cd build
cmake ..
make
sudo make install
```
### windows

## 命令行参数
```shell
    --help(-h) for help.
    --version(-v) for version info.

    --file(-f), pcap file to parse,default model,without -c.
    --json(-j), json match condition,from file.
    --filter(-f), cmd line filter condition,like wireshark.
    --save(-s), log output to file,without this option,log output to console.
    --max(-m), print msg by bytes up to max,without this option or 0,do not print msg details.

    --compare(-c),compare by byte,must option:file1,file2,can use --json and --filter conditions.
    --file1(-a),one of pcap file for compare.
    --file2(-b),one of pcap file for compare.
    --start(-k), compare model,the begin offset of msg,without this option begin offset is 0.
    --end(-l), compare model,the end offset of msg,without this option end offset is 0.
```
### 使用示例1，过滤报文
要解析的pcap文件是ens33.pcap，filter过滤条件是'udp.length<400'，json匹配条件文件是../config/filter.json，最多打印100个字节的报文内容，结果输出到控制台，以太协议类型、IP头、TCP/UDP头和json匹配字段高亮显示。
```shell
./idump --file=ens33.pcap --filter='udp.length<500' --json=../config/filter.json --max=100
```
![demo1](https://github.com/wichue/idump/blob/master/res/demo1.png)
### 使用示例2，比对报文
-c比对模式，比较ens33.pcap和ens33_2.pcap两个抓包文件，满足filter和json匹配条件，每帧报文首部偏移14个字节，尾部偏移4个字节，结果保存到22.txt文件。
```shell
./idump -c --file1=ens33.pcap --file2=ens33_2.pcap --filter=udp --json=../config/filter.json --start=14 --end=4 --save=22.txt
```
![demo2](https://github.com/wichue/idump/blob/master/res/demo2.png)

## --json匹配条件，自定义协议过滤
- name：json条件名。
- start：每一帧匹配的开始字节位置，从0开始。
- compare：要匹配的16进制串，2位表示一个字节，2的整数倍。
- compare：支持通配符*，2个*表示一个字节，通配任何字节， *的个数是2的整数倍。
- desc：满足当前匹配条件的描述，会显示在打印输出的最后一列。
- 示例文件：config/filter.json，json数组列出了3个条件，多个条件是或的关系，优先匹配排在前面的条件，满足任意一个即是满足json条件。
```shell
{
    "name": "cond1",
    "conds": [
        {
            "start": "42",
            "compare": "7e60",
            "desc": "heart"
        },
        {
            "start": "72",
            "compare": "00030b64",
            "desc": "hand"
        },
        {
            "start": "12",
            "compare": "86dd********0193",
            "desc": "ipv6_com"
        }
    ]
}
```

## --filter过滤条件，使用``单引号包围
实现了常用的wireshark过滤条件。
- frame
```shell
frame.len==60		# 包的长度
frame.cap_len==60	# 实际捕获包的长度
frame.number==20	# 帧序号
```

- eth
```shell
eth.dst
eth.dst==00-0c-29-95-c3-db	# 目的MAC
eth.dst==00:0c:29:95:c3:db	# 目的MAC
eth.src==00:0c:29:95:c3:db	# 源MAC
eth.type==0800	# 16进制，协议类型
eth.type==86dd	# 16进制，协议类型
```
- ipv4
```shell
ip					# ipv4报文
ip.hdr_len==20		# ip头长度
ip.version==4		# ip版本
ip.tos!=0			# 服务类型
ip.len>=80			# ip头和负载总长度
ip.id==b625			# 16进制，标识
ip.fragment==0		# 分段偏移
ip.ttl==128			# TTL
ip.proto==17		# 协议类型，17(udp);6(tcp)
ip.checksum==f0c3	# 16进制，校验和
ip.src_host==192.168.220.128	# 源ip
ip.dst_host==192.168.220.2		# 目的ip
```
- ipv6
```shell
ipv6				# ipv6报文
ipv6.version==6		# ip版本
ipv6.plen>=400		# 除了ip头以外的负载长度
ipv6.nxt==17		# 协议类型，17(udp);6(tcp)
ipv6.src_host==fe80::9d30:4261:73d0:119f	# 源ip
ipv6.dst_host==ff02::fb						# 目的ip
```
- tcp
```shell
tcp						# tcp报文
tcp.hdr_len==20			# tcp头部长度
tcp.srcport>=10000		# 源端口
tcp.dstport < 10000		# 目的端口
tcp.seq > 294723434		# 序列号
tcp.ack < 294723434		# 确认号
tcp.fin==1				# 发送方要释放一个链接
tcp.syn==1				# 同步序号，用于建立链接过程
tcp.reset==1			# 重置一个错误的链接
tcp.push==1				# 
tcp.ack_flag==1			# ack位被设置为1表示tcphdr->ack_seq是有效的，如果ack为0，则表示该数据段不包含确认信息
tcp.urg==1				# 紧急位
tcp.ece==1
tcp.cwr==1
tcp.windows_size==64240	# 滑动窗口大小
tcp.checksum==5de1		# 校验和，16进制
tcp.urgent_pointer==0	# 这个域被用来指示紧急数据在当前数据段中的为止
```
- udp
```shell
udp						# udp报文
udp.srcport==58339		# 源端口
udp.dstport==53			# 目的端口
udp.length==69			# udp头和负载的总长度
udp.checksum==3a2b		# 校验和，16进制
```
- 比较运算符：
```shell
==		# 等于
!=		# 不等于
>		# 大于
>=		# 大于等于
<		# 小于
<=		# 小于等于
!		# 非
```
- 组合条件示例
```shell
ip.dst_host==192.168.220.128 && tcp.dstport == 49970
ip.dst_host==192.168.220.128 || ip.dst_host==34.149.100.209
```

## --compare(-c)比对模式
按字节比较两个pcap文件，可设置过滤条件和每个报文的首部和尾部偏移，用于分析丢包、错包、乱包等。
- --compare(-c)选项启用比对模式。
- 必须的选项：--file1 和 --file2，参与比对的两个pcap文件路径。
- 可选选项： --start 和 --end，分别表示比对的时首部和尾部要忽略的字节数量，比如忽略开始的12字节mac头，忽略尾标等。
- 可使用 --json 和 --filter 条件进行过滤。
- 满足过滤条件的报文，忽略指定数量的头部和尾部，按字节进行比较；结果给出第一个不相同字节所在的帧序号和帧的第多少个字节。


