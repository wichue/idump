#ifndef __COMMON_PROTOCOL_H
#define __COMMON_PROTOCOL_H

#include <stdint.h>
#include <string>

namespace chw {

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

// ethnet协议头
struct EthnetHeader_t 
{
    unsigned char srcMac[6];
    unsigned char dstMac[6];
    uint16_t protoType;
};

//IP数据报头 20字节
struct IPHeader_t
{
    uint8_t Ver_HLen;       //版本+报头长度
    uint8_t TOS;            //服务类型
    uint16_t TotalLen;       //总长度
    uint16_t ID; //标识
    uint16_t Flag_Segment;   //标志+片偏移
    uint8_t TTL;            //生存周期
    uint8_t Protocol;       //协议类型
    uint16_t Checksum;       //头部校验和
    uint32_t SrcIP; //源IP地址
    uint32_t DstIP; //目的IP地址
};

// UDP头 (8字节)
struct UDPHeader_t
{
    uint16_t SrcPort;    // 源端口号16bit
    uint16_t DstPort;    // 目的端口号16bit
    uint16_t Length;     // 长度
    uint16_t CheckSum;   // 校验码
};

// TCP头 (20字节)
struct TCPHeader_t 
{
    uint16_t srcPort;          // 源端口
    uint16_t dstPort;          // 目的端口
    uint32_t SeqNo;            // 序列号
    uint32_t AckNo;            // 确认号
    uint16_t headAndFlags;     // 首部长度即标志位
    uint16_t WinSize;          // 窗口大小
    uint16_t CheckSum;         // 校验和
    uint16_t UrgPtr;           // 紧急指针
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

    uint16_t max;//每帧打印报文的最大字节数(--max)，默认160，0则不打印报文内容

    ConfigCmd()
    {
        file = nullptr;
        filter = nullptr;
        save = nullptr;
        start = 0;
        end = 0;
        max = 160;
    }
};

//从json文件读取的匹配条件
struct CondJson
{
    uint16_t start;//比较的起始位置，从1开始
    std::string compare;//要比较的16进制字符串，和该字符串相同则满足条件，*为通配符
    std::string desc;//满足当前条件报文的描述，会输出到日志上
};

} // namespace chw
#endif //__COMMON_PROTOCOL_H