#ifndef __COMMON_PROTOCOL_H
#define __COMMON_PROTOCOL_H

#include <stdint.h>
#include <string>

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
    uint32_t caplen; /* length of portion present */
    uint32_t len;    /* length this packet (off wire) */
};

// 以太头
struct ethhdr {
	unsigned char	h_dest[ETH_ALEN];	/* destination eth addr	*/
	unsigned char	h_source[ETH_ALEN];	/* source ether addr	*/
	uint16_t		h_proto;		/* packet type ID field	*/
} __attribute__((packed));

// ipv4头
struct iphdr {
	uint8_t	ihl:4,//首部长度(4位),表示IP报文头部按32位字长（32位，4字节）计数的长度，也即报文头的长度等于IHL的值乘以4。
		version:4;//版本(4位)
	uint8_t	tos;// 服务类型字段(8位)
	uint16_t	tot_len;//总长度字段(16位)是指整个IP数据报的长度
	uint16_t	id;//总长度字段(16位)是指整个IP数据报的长度,
	uint16_t	frag_off;//分段偏移
	uint8_t	ttl;//TTL
	uint8_t	protocol;//协议字段
	uint16_t	check;//首部校验和字段
	uint32_t	saddr;//32源IP地址
	uint32_t	daddr;//32位目的IP地址
	/*The options start here. */
};

// ipv6头
typedef struct _IP6Hdr
{
    uint32_t version:4;// ip版本，6
    uint32_t priority:8;// 通信优先级
    uint32_t flow_lbl:20;// 流标签，可用来标记报文的数据流类型，以便在网络层区分不同的报文。
    uint16_t payload_len; // PayLoad Length 除了ipv6头部以外的负载长度(传输层+应用层长度)
    uint8_t nexthdr; // Next Header 可能是tcp/udp协议类型，也可能是IPv6扩展报头
    uint8_t hop_limit; // Hop Limit 跳数限制
    uint8_t saddr[16];// 源IP地址
    uint8_t daddr[16];// 目的IP地址
} IP6Hdr;

// ipv6扩展头
typedef struct _IP6ExtenHdr
{
    uint8_t Ex_Next_Hdr;
    uint8_t Ex_Hdr_len;
    uint16_t reserve16;
    uint32_t reserve32;
}IP6ExtenHdr;

struct udphdr {
	uint16_t	source;//源端口号
	uint16_t	dest;//目的端口号
	uint16_t	len;//整个UDP数据报的长度 = 报头+载荷。
	uint16_t	check;//检测UDP数据(包含头部和数据部分)报在传输中是否有错，有错则丢弃
};

struct tcphdr {
	uint16_t	source;//16位源端口
	uint16_t	dest;//16位目的端口
	uint32_t	seq;//序列号
	uint32_t	ack_seq;//确认号
// #if defined(__LITTLE_ENDIAN_BITFIELD)
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
// #elif defined(__BIG_ENDIAN_BITFIELD)
// 	__u16	doff:4,
// 		res1:4,
// 		cwr:1,
// 		ece:1,
// 		urg:1,
// 		ack:1,
// 		psh:1,
// 		rst:1,
// 		syn:1,
// 		fin:1;
// #else
// #error	"Adjust your <asm/byteorder.h> defines"
// #endif	
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

	uint8_t ipver;//ip协议类型
	union {
		iphdr* ip4;
		IP6Hdr* ip6;
	};

    uint8_t transport;//传输层类型
	union {
		tcphdr* tcp;
		udphdr* udp;
	};

    ayz_info()
    {
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

//命令行参数
struct ConfigCmd
{
    char* file;//pcap文件名(--file)
    char* filter;//过滤器(--filter)
    char* json;//过滤条件，从json文件读取(--json)
    char* save;//要保存的文件名(--save)，没有该选项则输出到屏幕

    uint32_t start;//处理报文时首部忽略的字节数(--start)，没有该选项默认为0
    uint32_t end;//处理报文时尾部忽略的字节数(--end)，没有该选项默认为0

    uint16_t max;//每帧打印报文的最大字节数(--max)，默认0不打印报文内容

    ConfigCmd()
    {
        file = nullptr;
        filter = nullptr;
        save = nullptr;
        start = 0;
        end = 0;
        max = 0;
    }
};

//从json文件读取的匹配条件
struct CondJson
{
    uint16_t start;//比较的起始位置，从1开始
    std::string compare;//要比较的16进制字符串，和该字符串相同则满足条件，*为通配符
    std::string desc;//满足当前条件报文的描述，会输出到日志上
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
    _GREATER,           // >
    _GREATER_EQUAL,     // >=
    _LESS,              // <
    _LESS_EQUAL         // <=
};

// 条件表达式的协议类型
enum _protocol {
    _frame, //frame
    _eth,   //eth
    _ip,    //ip
    _arp,   //arp
    _tcp,   //tcp
    _udp,   //udp
};

// frame的条件选项
enum frame_option {
	frame_len,
	frame_cap_len
};

// eth的条件选项
enum eth_option {
    eth_dst,
    eth_src,
    eth_type
};

// ip的条件选项
enum ip_option {
    ip_hdr_len,
    ip_version,
    ip_tos,
    ip_len,
    ip_id,
    ip_fragment,
    ip_ttl,
    ip_proto,
    ip_checksum,
    ip_saddr,
    ip_daddr,
};

// tcp的条件选项
enum tcp_option {
    tcp_hdr_len,
    tcp_srcport,
    tcp_dstport,
    tcp_seq,
    tcp_ack,

    tcp_fin,
    tcp_syn,
    tcp_reset,
    tcp_push,
    tcp_ack_flag,
    tcp_urg,
    tcp_ece,
    tcp_cwr,

    tcp_window_size,
    tcp_checksum,
    tcp_urgent_pointer
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
    bool bValid = false;// 是否有效的条件
    and_or ao;// 与上一个FilterCond是 && 还是 || 关系

    std::string desc;// 来自命令行的原始条件表达式
    _operator op;// 比较运算符
    std::string exp_front;// 比较运算符前面的表达式
    std::string exp_back;// 比较运算符后面的表达式
    bool non = false;// 最前面是否包含 ! 运算符，最多只能有一个!运算符，不像wireshark可以嵌套多个

    _protocol potol;// 协议类型
    uint16_t option_val;// 协议的参数选项
};



} // namespace chw
#endif //__COMMON_PROTOCOL_H
