// Copyright (c) 2024 The idump project authors. SPDX-License-Identifier: MIT.
// This file is part of idump(https://github.com/wichue/idump).

#ifndef __COMMON_PROTOCOL_H
#define __COMMON_PROTOCOL_H

#include <stdint.h>
#include <string>
#include <netinet/in.h>// for in_addr in6_addr
#include <vector>

namespace chw {

#ifndef ETH_ALEN
#define ETH_ALEN    6
#endif

#pragma pack(1)
//pacp文件头结构体
struct pcap_file_header
{
    uint32_t magic;       /* 0xa1b2c3d4 */
    uint16_t version_major;   /* magjor Version 2 */
    uint16_t version_minor;   /* magjor Version 4 */
    uint32_t thiszone;      /* gmt to local correction */
    uint32_t sigfigs;     /* accuracy of timestamps */
    uint32_t snaplen;     /* max length saved portion of each pkt */
    uint32_t linktype;    /* data link type (LINKTYPE_*) */
};

//时间戳
struct time_val
{
    int tv_sec;         /* seconds 含义同 time_t 对象的值 */
    int tv_usec;        /* and microseconds */
};

//pcap数据包头结构体
struct pcap_pkthdr
{
    struct time_val ts;  /* time stamp */
    uint32_t caplen; /* length of portion present 实际捕获包的长度*/
    uint32_t len;    /* length this packet (off wire) 包的长度*/
};

// 以太头
struct ethhdr {
	unsigned char	h_dest[ETH_ALEN];	/* destination eth addr	*/
	unsigned char	h_source[ETH_ALEN];	/* source ether addr	*/
	uint16_t		h_proto;		/* packet type ID field	*/
} __attribute__((packed));

/*
 *  * IPV4头，最小20字节
 *  *
 *  0      3 4     7 8            15 16    19                         31
 *  +-------+-------+---------------+----------------------------------+
 *  |VER(4b)|LEN(4b)|  TOS(8b)      |       TOTAL LEN(16bit)           |
 *  +-------+-------+---------------+-----+----------------------------+ 4B
 *  |       identifier 16bit        |FLAGS|      OFFSET (13bit)        |
 *  +---------------+---------------+-----+----------------------------+ 8B
 *  |    TTL 8bit   | protocol 8bit |     checksum 16bit               |
 *  +---------------+---------------+----------------------------------+ 12B
 *  |                  32bit src IP                                    |
 *  +------------------------------------------------------------------+ 16B
 *  |                  32bit dst IP                                    |
 *  +------------------------------------------------------------------+ 20B
 *  \                  OPTION (if has)                                 /
 *  /                                                                  \
 *  +------------------------------------------------------------------+
 *  |                                                                  |
 *  |                     DATA...                                      |
 *  +------------------------------------------------------------------+
 *  */
// ipv4头
struct ip4hdr {
#if defined(__LITTLE_ENDIAN)
	uint8_t	ihl:4,//首部长度(4位),表示IP报文头部按32位字长（32位，4字节）计数的长度，也即报文头的长度等于IHL的值乘以4。
			version:4;//版本(4位)
#elif defined(__BIG_ENDIAN)
	uint8_t	version:4;//版本(4位)
			ihl:4,//首部长度(4位),表示IP报文头部按32位字长（32位，4字节）计数的长度，也即报文头的长度等于IHL的值乘以4。
#endif
	uint8_t	tos;// 服务类型字段(8位)
	uint16_t	tot_len;//总长度字段(16位)是指整个IP数据报的长度
	uint16_t	id;//标识，用于分片处理，同一数据报的分片具有相同的标识
	uint16_t	frag_off;//分段偏移
	uint8_t	ttl;//TTL
	uint8_t	protocol;//协议字段
	uint16_t	check;//首部校验和字段
	uint32_t	saddr;//32源IP地址
	uint32_t	daddr;//32位目的IP地址
	/*The options start here. */
};

/*  IPV6头，固定长度40字节
 *
 *  0      3 4     7 8   11 12    15 16                               31
 *  +-------+-------+------+-------------------------------------------+
 *  |ver(4b)|  TYPE(8bit)  |      stream  tag (20bit)                  |
 *  +-------+--------------+--------+----------------+-----------------+ 4B
 *  |    payload len (16bit)        |next head (8bit)|  jump limit (8b)|
 *  +-------------------------------+----------------+-----------------+ 8B
 *  |                   src IPV6 addr (128bit)                         |
 *  +------------------------------------------------------------------+ 12B
 *  |                     ..............                               |
 *  +------------------------------------------------------------------+ 16B
 *  |                     ..............                               |
 *  +------------------------------------------------------------------+ 20B
 *  |                     ..............                               |
 *  +------------------------------------------------------------------+ 24B
 *  |                   dst IPV6 addr (128bit)                         |
 *  +------------------------------------------------------------------+ 28B
 *  |                     ..............                               |
 *  +------------------------------------------------------------------+ 32B
 *  |                     ..............                               |
 *  +------------------------------------------------------------------+ 36B
 *  |                     ..............                               |
 *  +------------------------------------------------------------------+ 40B
 *  */
// ipv6头
typedef struct _IP6Hdr
{
#if defined(__LITTLE_ENDIAN)
    uint32_t flow_lbl:20;// 流标签，可用来标记报文的数据流类型，以便在网络层区分不同的报文。
    uint32_t priority:8;// 通信优先级
    uint32_t version:4;// ip版本，6
#elif defined(__BIG_ENDIAN)
    uint32_t version:4;// ip版本，6
    uint32_t priority:8;// 通信优先级
    uint32_t flow_lbl:20;// 流标签，可用来标记报文的数据流类型，以便在网络层区分不同的报文。
#endif
    uint16_t payload_len; // PayLoad Length 除了ipv6头部以外的负载长度(传输层+应用层长度)
    uint8_t nexthdr; // Next Header 可能是tcp/udp协议类型，也可能是IPv6扩展报头
    uint8_t hop_limit; // Hop Limit 跳数限制
    uint8_t saddr[16];// 源IP地址
    uint8_t daddr[16];// 目的IP地址
} ip6hdr;

// ipv6扩展头
typedef struct _IP6ExtenHdr
{
    uint8_t Ex_Next_Hdr;
    uint8_t Ex_Hdr_len;
    uint16_t reserve16;
    uint32_t reserve32;
}IP6ExtenHdr;

/*
 * udp头，长度固定8字节
 *
	0                       15 16                     31
	+-------------------------+------------------------+
	|     src Port 16bit      |   dst Port 16bit       |
	+-------------------------+------------------------+
	|     data len 16bit      |   checksum 16bit       |
	+-------------------------+------------------------+
*/
struct udphdr {
	uint16_t	source;//源端口号
	uint16_t	dest;//目的端口号
	uint16_t	len;//整个UDP数据报的长度 = 报头+载荷。
	uint16_t	check;//检测UDP数据(包含头部和数据部分)报在传输中是否有错，有错则丢弃
};

/*tcp头，最小20字节
 *
   0                   1                   2                   3   
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Source Port(16bit)   |       Destination Port(16bit) |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Sequence Number(32bit)                 |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Acknowledgment Number(32bit)               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Data |           |U|A|P|R|S|F|                               |
   | Offset| Reserved  |R|C|S|S|Y|I|            Window(16bit)      |
   |  4bit |  16bit    |G|K|H|T|N|N|                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Checksum 16bit      |         Urgent Pointer 16bit  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             data                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct tcphdr {
	uint16_t	source;//16位源端口
	uint16_t	dest;//16位目的端口
	uint32_t	seq;//序列号
	uint32_t	ack_seq;//确认号
#if defined(__LITTLE_ENDIAN)
	uint16_t	res1:4,// 保留位
		doff:4,//TCP头长度，指明了TCP头部包含了多少个32位的字
		fin:1,//释放一个连接，它表示发送方已经没有数据要传输了。
		syn:1,//同步序号，用来发送一个连接。syn被用于建立连接的过程。
		rst:1,//该位用于重置一个混乱的连接，之所以混乱，可能是因为主机崩溃或者其他原因。
		psh:1,
		ack:1,//ack位被设置为1表示tcphdr->ack_seq是有效的，如果ack为0，则表示该数据段不包含确认信息
		urg:1,//紧急指针有效
		ece:1,
		cwr:1;
#elif defined(__BIG_ENDIAN)
 	__u16	doff:4,
 		res1:4,
 		cwr:1,
 		ece:1,
 		urg:1,
 		ack:1,
 		psh:1,
 		rst:1,
 		syn:1,
 		fin:1;
#endif	
	uint16_t	window;//16位滑动窗口大小，单位为字节，起始于确认序号字段指明的值，这个值是接收端期望接收的字节数，其最大值为63353字节。
	uint16_t	check;//校验和，覆盖了整个tcp报文端，是一个强制性的字段，一定是由发送端计算和存储，并由接收端进行验证。
	uint16_t	urg_ptr;//  这个域被用来指示紧急数据在当前数据段中的为止，它是一个相当于当前序列号的字节偏移量。这个设置可以代替中断信息。
};

typedef enum {
    IPV4 = 4,
    IPV6 = 6,
    IP_NULL
} _IPTYPE_;

typedef enum {
    tcp_trans,
    udp_trans,
    null_trans
} _TRANSPORT_;

// 解析一条pcap帧获得的信息
struct ayz_info {
	pcap_pkthdr* pcap;//frame包头
	ethhdr* eth;//以太头
	uint32_t uIndex;// 帧序号
	uint32_t json_start;// 匹配到的json条件的起始位置
	uint32_t json_end;// 匹配搭配的json条件的终止位置

	uint8_t ipver;//ip协议类型
	union {
		ip4hdr* ip4;
		ip6hdr* ip6;
	};

    uint8_t transport;//传输层类型
	union {
		tcphdr* tcp;
		udphdr* udp;
	};

    ayz_info()
    {
		uIndex = 0;
        pcap = nullptr;
        eth = nullptr;
        ip4 = nullptr;
        ip6 = nullptr;
        tcp = nullptr;
        udp = nullptr;

        ipver = IP_NULL;
        transport = null_trans;
    }
};

#pragma pack()

enum chw_ret{
    success,
    fail
};

struct ComMatchBuf{
	char* buf;// 满足匹配条件的待比对的buffer
	size_t size;// buffer的长度
	bool first;// 第一次比对会找出buf中不同字节的的序号，第二次比对会找出不同字节的帧序号和帧的第多少个字节
	uint32_t uDiff;// 第一次比对找出的不同字节序号
	uint32_t compare_count;// 参与比对帧的数量，既要满足匹配条件，也要满足start和end的长度

	ComMatchBuf()
	{
		buf = nullptr;
		size = 0;
		first = true;
		uDiff = 0;
		compare_count = 0;
	}
};

//命令行参数
struct ConfigCmd
{
    char* file;//pcap文件名(--file)
    char* filter;//过滤器(--filter)
    char* json;//过滤条件，从json文件读取(--json)
    char* save;//要保存的文件名(--save)，没有该选项则输出到屏幕
    uint16_t max;//每帧打印报文的最大字节数(--max)，默认0不打印报文内容

	//compare model
	//比对模式，filter和json过滤条件依然有效，不再按帧输出日志，会输出比对结果
	bool bCmp;//是否启动比对模式,是则必须输入 file1 和 file2 选项,不能有 file 选项(-c,--compare)
	char* file1;//参与比对的文件1(--file1)
	char* file2;//参与比对的文件2(--file2)
    uint32_t start;//比对报文时首部忽略的字节数(--start)，没有该选项默认为0
    uint32_t end;//比对报文时尾部忽略的字节数(--end)，没有该选项默认为0


    ConfigCmd()
    {
        file = nullptr;
        filter = nullptr;
		json = nullptr;
        save = nullptr;
        max = 0;

		bCmp = false;
		file1 = nullptr;
		file2 = nullptr;
        start = 0;
        end = 0;
    }
};

//分隔后的字符串，标识该字符串在原字符串的开始位置
struct spit_string{
	uint32_t uIndex;	//该字段的开始位置,单位字节
	std::string str;	//字段
};

//从json文件读取的匹配条件
struct CondJson
{
    uint16_t start;//比较的起始位置，从0开始
    std::string compare;//要比较的16进制字符串，和该字符串相同则满足条件，*为通配符，2个*表示一个字节
    std::string desc;//满足当前条件报文的描述，会输出到日志上

	uint32_t totalLen;//匹配条件的总字节数量，包含通配符
	std::vector<spit_string> vsCompare;//由通配符分隔的多个匹配字段
};

// 条件表达式之间的关系运算符
enum and_or {
    _and,// &&
    _or, // ||
	_null // no pre
};

// 条件表达式的关系运算符
enum _operator {
    _EQUAL,             // ==
	_UNEQUAL,		    // !=
    _GREATER,           // >
    _GREATER_EQUAL,     // >=
    _LESS,              // <
    _LESS_EQUAL         // <=
};

// 条件表达式的协议类型
enum _protocol {
    _frame, //frame
    _eth,   //eth
    _ip,    //ipv4
    _ipv6,  //ipv6
    _arp,   //arp
    _tcp,   //tcp
    _udp,   //udp
};

// frame的条件选项
enum frame_option {
	frame_len,      // 帧长度
	frame_cap_len,  // 捕获长度
	frame_number	// 帧序号
};

// eth的条件选项
enum eth_option {
    eth_dst,    //目的MAC
    eth_src,    //源MAC
    eth_type    //协议类型
};

// ipv4的条件选项
enum ip_option {
    ip_hdr_len,     //ip头长度
    ip_version,     //ip版本
    ip_tos,         //服务类型
    ip_len,         //ip头和负载的总长度
    ip_id,          //
    ip_fragment,    //分段偏移
    ip_ttl,         //TTL
    ip_proto,       //协议字段
    ip_checksum,    //首部校验和字段
    ip_src_host,       //32源IP地址
    ip_dst_host,       //32位目的IP地址
};

// ipv6的条件选项
enum ipv6_option {
    ipv6_version,     //ip版本
    ipv6_flow,         //流标签:todo
    ipv6_plen,         //除了ipv6头部以外的负载长度(传输层+应用层长度)
    ipv6_nxt,          //Next Header 可能是tcp/udp协议类型，也可能是IPv6扩展报头
    ipv6_src_host,     //源IP地址
    ipv6_dst_host,     //目的IP地址
};

// tcp的条件选项
enum tcp_option {
    tcp_hdr_len,    //tcp头长度
    tcp_srcport,    //16位源端口
    tcp_dstport,    //16位目的端口
    tcp_seq,        //序列号
    tcp_ack,        //确认号

    tcp_fin,        //释放一个连接
    tcp_syn,        //同步序号
    tcp_reset,      //该位用于重置一个混乱的连接
    tcp_push,
    tcp_ack_flag,   //ack位被设置为1表示tcphdr->ack_seq是有效的，如果ack为0，则表示该数据段不包含确认信息
    tcp_urg,        //紧急指针有效
    tcp_ece,    
    tcp_cwr,

    tcp_window_size,    //16位滑动窗口大小
    tcp_checksum,       //校验和，覆盖了整个tcp报文端
    tcp_urgent_pointer  //这个域被用来指示紧急数据在当前数据段中的为止
};

// udp的条件选项
enum udp_option {
    udp_srcport,    // 源端口号
    udp_dstport,    // 目的端口号
    udp_length,     // udp报头+负载的总长度
    udp_checksum    // 头部和数据部分校验和
};



// 条件表达式
//demo:
//tcp.dstport == 80	# desc
//==				# op
//tcp.dstport		# exp_front
//80 				# exp_back
//tcp 				# protol
//dstport 			# po_value
struct FilterCond {
    // bool bValid = false;// 是否有效的条件
    and_or ao;// 与上一个FilterCond是 && 还是 || 关系

    std::string desc;// 来自命令行的原始条件表达式    
    std::string exp_front;// 比较运算符前面的表达式
    std::string exp_back;// 比较运算符后面的表达式，为空则没有后置表达式
    //exp_back 后置表达式，根据 option_val 的不同进行转换
    union {
        struct in_addr ipv4;
        struct in6_addr ipv6;
        uint8_t mac[6];
        uint32_t int_comm;//用于存储整型
    };

    bool non = false;// 最前面是否包含 ! 运算符，最多只能有一个!运算符，不像wireshark可以嵌套多个
    _operator op;// 比较运算符
    _protocol potol;// 解析exp_front获得，协议类型： /_frame/_eth/_ip/_arp/_tcp/_udp
    uint16_t option_val;// 解析exp_front获得，协议的选项参数： frame_option/eth_option/ip_option/tcp_option/udp_option
};



} // namespace chw
#endif //__COMMON_PROTOCOL_H
