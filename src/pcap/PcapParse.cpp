#include "PcapParse.h"
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <arpa/inet.h>

#include "Logger.h"
#include "MemoryHandle.h"
#include "GlobalValue.h"

void PcapParse::parse(const char* filename)
{
    struct stat st;
    if (stat(filename, &st))
    {
        printf("stat file %s failed, errno=%d errmsg=%s\n", filename, errno, strerror(errno));
        return;
    }

    size_t fileSize = st.st_size;

    if (!fileSize)
    {
        printf("file is empty!\n");
        return;
    }

    char *buf = (char*)malloc(fileSize + 1);

    FILE* fp = fopen(filename, "r");
    if (!fp)
    {
        printf("open file %s failed, errno=%d errmsg=%s\n", filename, errno, strerror(errno));
        return;
    }
    fread(buf, sizeof(char), fileSize, fp);
    fclose(fp);


    size_t offset = 0;
    // pcap 文件头
    chw::pcap_file_header* fileHeader = (chw::pcap_file_header*)(buf + offset);
    offset += sizeof(chw::pcap_file_header);
    PrintD("pcap file - magic:%#x version:%d.%d,snaplen:%u", fileHeader->magic, fileHeader->version_major, fileHeader->version_minor,fileHeader->snaplen);

    resolve_each_frame(fileSize,offset,buf);

    if (buf)
    {
        free(buf);
        buf = NULL;
    }
}

uint32_t PcapParse::resolve_each_frame(size_t fileSize, size_t offset, char* buf)
{
    PrintD("No.     time                    Source                          Destination                     protocol  len     desc      ");

    size_t proto_offset = 0;//以太头偏移
    mPackIndex = 0;
    while (offset < fileSize)
    {
        // pcap 包头
        chw::pcap_pkthdr* pcapHeader = (chw::pcap_pkthdr*)(buf + offset);
        proto_offset = offset + sizeof(chw::pcap_pkthdr);

        offset += (pcapHeader->caplen + sizeof(chw::pcap_pkthdr));
        mPackIndex++;

        //匹配json过滤条件
        std::string desc = match_json(buf + proto_offset, pcapHeader->caplen);
        if(desc.size() == 0)
        {
            continue;
        }
        
        // 以太头
        chw::ethhdr* ethHeader = (chw::ethhdr*)(buf + proto_offset);
        uint16_t protocol = ntohs(ethHeader->h_proto);

        // 协议类型，如果是ipv4或ipv6，且是已知的tcp/udp等传输层协议，则显示传输层协议，如果是未知的则显示16进制值
        std::string str_Protocol = chw::HexBuftoString((const unsigned char*)&ethHeader->h_proto,2);//0800,86dd
        // ipv4和ipv6显示目的IP地址，其他显示目的MAC地址
        std::string str_Destination = chw::MacBuftoStr((const unsigned char*)(ethHeader->h_dest));
        // ipv4和ipv6显示源IP地址，其他显示源MAC地址
        std::string str_Source = chw::MacBuftoStr((const unsigned char*)(ethHeader->h_source));

        // ip 协议
        switch(protocol)
        {
            case 0x0800:
                str_Protocol = "ipv4";
                Ipv4Decode(buf + proto_offset + sizeof(chw::ethhdr), str_Protocol, str_Destination, str_Source);
                break;
            case 0x86dd:
                str_Protocol = "ipv6";
                Ipv6Decode(buf + proto_offset + sizeof(chw::ethhdr), str_Protocol, str_Destination, str_Source);
            break;

            // 其他自定义协议
            default:
            break;
        }


        //输出日志
        //No.       time                          Source          Destination     protocol  len       desc      
        PrintD("%-8u%-24s%-32s%-32s%-10s%-8u%-10s"
        ,mPackIndex
        ,chw::getTimeStr("%Y-%m-%d %H:%M:%S",time_t(pcapHeader->ts.tv_sec)).c_str()
        ,str_Source.c_str()
        ,str_Destination.c_str()
        ,str_Protocol.c_str()
        ,pcapHeader->caplen
        ,desc.c_str());

        if(gConfigCmd.max > 0)
        {
            chw::PrintBuffer(buf + proto_offset, pcapHeader->caplen);
        }
    }

    PrintD("total package count:%d", mPackIndex);

    return 0;
}

std::string PcapParse::match_json(char* buf, size_t size)
{
    std::string desc = "";
    auto iter = g_vCondJson.begin();
    while(iter != g_vCondJson.end())
    {
        if(iter->start >= size)
        {
            continue;
        }

        if(iter->start + iter->compare.size() -1 > size)
        {
            continue;
        }

        if(iter->compare.size() == 0)
        {
            continue;
        }

        //todo:匹配通配符
        if(_CMP_MEM_(iter->compare.c_str(), iter->compare.size(), buf + iter->start - 1, iter->compare.size()) == 0)
        {
            desc = iter->desc;
            break;
        }
        iter ++;
    }

    return desc;
}

// ipv4 协议解析
void PcapParse::Ipv4Decode(const char* buf, std::string& pro, std::string& des, std::string& src)
{
    chw::iphdr* ipHeader = (chw::iphdr*)(buf);

    std::string srcIp = chw::sockaddr_ipv4(ipHeader->saddr);
    std::string dstIp = chw::sockaddr_ipv4(ipHeader->daddr);

    srcIp.size() == 0 ? 0 :src = srcIp;
    dstIp.size() == 0 ? 0 :des = dstIp;

    uint16_t toal_len = ntohs(ipHeader->tot_len);// IP头+后面负载总长度
    uint16_t head_len  = ipHeader->ihl * 4;// ip头长度

    // todo:匹配ip过滤条件
    
    switch (ipHeader->protocol)
    {
        case 17:// UDP协议
            pro = "udp";
            UdpDecode(buf + head_len);
            break;
        case 6: // TCP协议
            pro = "tcp";
            TcpDecode(buf + head_len, toal_len - head_len);
            break;
        default:
            // 其他协议，待补充
            break;
    }
}

// ipv6 协议解析
void PcapParse::Ipv6Decode(const char* buf, std::string& pro, std::string& des, std::string& src)
{
    chw::IP6Hdr* ipHeader = (chw::IP6Hdr*)(buf);

    std::string srcIp = chw::sockaddr_ipv6(ipHeader->saddr);
    std::string dstIp = chw::sockaddr_ipv6(ipHeader->daddr);

    srcIp.size() == 0 ? 0 :src = srcIp;
    dstIp.size() == 0 ? 0 :des = dstIp;

    uint16_t load_len = ntohs(ipHeader->payload_len);// 后面负载总长度
    uint16_t head_len  = sizeof(chw::IP6Hdr);// ip头长度

    // todo:匹配ip过滤条件
    
    switch (ipHeader->nexthdr)
    {
        case 17:// UDP协议
            UdpDecode(buf + head_len);
            break;
        case 6: // TCP协议
            TcpDecode(buf + head_len, load_len);
            break;
        default:
            // 其他协议，待补充
            break;
    }
}

// udp协议解析
void PcapParse::UdpDecode(const char* buf)
{
    chw::udphdr* udpHeader = (chw::udphdr*)(buf);

    uint16_t srcPort = ntohs(udpHeader->source);
    uint16_t dstPort = ntohs(udpHeader->dest);
    // udp负载长度
    uint16_t loadLen = ntohs(udpHeader->len) - sizeof(chw::udphdr);

    // todo:匹配udp过滤条件

    // PrintD("udp srcPort=%d,dstPort=%d,loadLen=%u",srcPort,dstPort,loadLen);
}

// tcp协议解析
void PcapParse::TcpDecode(const char* buf, uint16_t len)
{
    chw::tcphdr* tcpHeader = (chw::tcphdr*)(buf);

    uint16_t srcPort = ntohs(tcpHeader->source);
    uint16_t dstPort = ntohs(tcpHeader->dest);
    // tcp负载长度
    uint16_t loadLen = len - tcpHeader->doff * 4;

    // todo:匹配tcp过滤条件

    // PrintD("tcp srcPort=%d,dstPort=%d,loadLen=%u",srcPort,dstPort,loadLen);
}
