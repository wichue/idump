# PCAP file parsing tool implemented in pure C++

[![](https://img.shields.io/badge/license-MIT-green.svg)](https://github.com/wichue/idump/blob/master/LICENSE)
[![](https://img.shields.io/badge/language-c++-red.svg)](https://en.cppreference.com/)
[![](https://img.shields.io/badge/platform-linux%20|%20windows-blue.svg)](https://github.com/wichue/idump)
## original intention
When analyzing massive PCAP packet capture data, quickly finding the message of interest is a headache, especially for some custom protocols. Which one is heartbeat and which one is authentication can only be viewed in bytes, and the protocol structure of each message needs to be memorized. Not familiar with the protocol is like reading a book, which is inefficient; After using tcpdump to capture packets on platforms such as Linux/ARM, it is usually difficult to copy them to an environment with Wireshark for viewing; When conducting packet loss analysis, it may feel like there are errors in packet loss, but it's important not to look at them one by one. We need to find out where the error occurred and have evidence to support it. We have developed this tool to address the issues in production mentioned above and encourage everyone to work together.
## Project characteristics
-Pure C++implementation, no other dependencies, easy to compile and use, supports Linux and Windows platforms.
-Command line terminal execution can be used in environments such as Linux and ARM where Wirshark is not convenient to use.
-Custom JSON filtering conditions, customizable for any private protocol filtering, not limited to conventional protocol filtering such as Wireshark.
-The comparison mode supports comparing two PCAP files by byte, and can set filtering conditions and header and tail offsets for each message to analyze packet loss, erroneous packets, and scrambled packets.
-Support commonly used conventional protocol filtering, with filtering commands similar to Wireshark.

## Compile and Install
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

## Command line parameters
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
### Example 1: Filtering Messages
The pcap file to be parsed is ens33.pcap, the filter condition is' udp.length<400 ', and the json matching condition file is/ config/filter.json， Print up to 100 bytes of message content, output the results to the console, and highlight the Ethernet protocol type, IP header, TCP/UDP header, and JSON matching fields.
```shell
./idump --file=ens33.pcap --filter='udp.length<500' --json=../config/filter.json --max=100
```
![demo1](https://github.com/wichue/idump/blob/master/res/demo1.png)
### Example 2: Compare Messages
-c,cmpare model，Compare two packet capture files, ens33.pcap and ens33_2. pcap, that meet the filter and json matching conditions. Each frame's message header is offset by 14 bytes and the tail is offset by 4 bytes. Save the results to a 22.txt file.
```shell
./idump -c --file1=ens33.pcap --file2=ens33_2.pcap --filter=udp --json=../config/filter.json --start=14 --end=4 --save=22.txt
```
![demo2](https://github.com/wichue/idump/blob/master/res/demo2.png)

## --json,Matching criteria, custom protocol filtering
-name: JSON condition name.
-start: The starting byte position of each frame match, starting from 0.
-compare: The hexadecimal string to be matched, with 2 bits representing one byte and an integer multiple of 2.
-compare: Supports wildcard characters *, where 2 * represent one byte. Any byte is compatible, and the number of * is an integer multiple of 2.
-desc: The description that meets the current matching criteria will be displayed in the last column of the printed output.
-Example file: config/filter. json. The json array lists three conditions, where multiple conditions have an OR relationship. Priority is given to matching the first condition, and satisfying any one of them satisfies the json condition.
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

## --filter,Filter criteria, enclosed in single quotes
Implemented commonly used Wireshark filtering conditions.
- frame
```shell
frame.len==60		# The length of the bag
frame.cap_len==60	# Actual length of captured package
frame.number==20	# Frame number
```

- eth
```shell
eth.dst
eth.dst==00-0c-29-95-c3-db	# Purpose MAC
eth.dst==00:0c:29:95:c3:db	# Purpose MAC
eth.src==00:0c:29:95:c3:db	# Source MAC
eth.type==0800	# Hexadecimal, protocol type
eth.type==86dd	# Hexadecimal, protocol type
```
- ipv4
```shell
ip					# IPv4 packet
ip.hdr_len==20		# IP header length
ip.version==4		# IP version
ip.tos!=0			# Service type
ip.len>=80			# Total length of IP header and payload
ip.id==b625			# Hexadecimal, identification
ip.fragment==0		# Segmented offset
ip.ttl==128			# TTL
ip.proto==17		# Protocol type，17(udp);6(tcp)
ip.checksum==f0c3	# Hexadecimal, checksum
ip.src_host==192.168.220.128	# Source ip
ip.dst_host==192.168.220.2		# Purpose ip
```
- ipv6
```shell
ipv6				# IPv6 packet
ipv6.version==6		# IP version
ipv6.plen>=400		# Load length other than IP header
ipv6.nxt==17		# Protocol type，17(udp);6(tcp)
ipv6.src_host==fe80::9d30:4261:73d0:119f	# Source ip
ipv6.dst_host==ff02::fb						# Purpose ip
```
- tcp
```shell
tcp						# TCP packet
tcp.hdr_len==20			# TCP header length
tcp.srcport>=10000		# Source port
tcp.dstport < 10000		# Destination port
tcp.seq > 294723434		# serial number
tcp.ack < 294723434		# Confirmation number
tcp.fin==1				# The sender wants to release a link
tcp.syn==1				# Synchronization number, used to establish the linking process
tcp.reset==1			# Reset an incorrect link
tcp.push==1				# 
tcp.ack_flag==1			# If the ack bit is set to 1, it means that tcphdr ->ack_deq is valid. If ack is 0, it means that the data segment does not contain confirmation information
tcp.urg==1				# Emergency position
tcp.ece==1
tcp.cwr==1
tcp.windows_size==64240	# Sliding window size
tcp.checksum==5de1		# Checksum, hexadecimal
tcp.urgent_pointer==0	# This field is used to indicate the duration of emergency data in the current data segment
```
- udp
```shell
udp						# UDP packet
udp.srcport==58339		# Source port
udp.dstport==53			# Destination port
udp.length==69			# The total length of UDP header and payload
udp.checksum==3a2b		# Checksum, hexadecimal
```
- Comparison operator:
```shell
==		# be equal to
!=		# Not equal to
>		# greater than
>=		# Greater than or equal to
<		# less than
<=		# Less than or equal to
!		# non
```
- Example of Combination Conditions
```shell
ip.dst_host==192.168.220.128 && tcp.dstport == 49970
ip.dst_host==192.168.220.128 || ip.dst_host==34.149.100.209
```

## --compare(-c),Comparison mode
Comparing two PCAP files by byte allows for setting filtering criteria and header and footer offsets for each message, which can be used to analyze packet loss, errors, and chaos.
-The 'compare (- c)' option enables the comparison mode.
-Required options: -- file1 and -- file2, the two pcap file paths involved in the comparison.
-Optional options: -- start and -- end, respectively indicating the number of bytes to be ignored in the header and footer during comparison, such as ignoring the starting 12 byte MAC header, ignoring the footer, etc.
-You can use -- json and -- filter conditions for filtering.
-Messages that meet the filtering criteria are compared by byte, ignoring the specified number of headers and tails; The result provides the frame number where the first different byte is located and the number of bytes in the frame.
