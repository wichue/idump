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
    PrintD("No.       time                          len       desc      ");

    size_t proto_offset = 0;
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
        chw::EthnetHeader_t* ethHeader = (chw::EthnetHeader_t*)(buf + proto_offset);
        uint16_t protocol = ntohs(ethHeader->protoType);

        
        // ip 协议
        switch(protocol)
        {
            case 0x0800:
                // ipDecode(buf + proto_offset);
                break;
            case 0x86dd:
            break;

            default:
            break;
        }


        //输出日志
        PrintD("%-10u%-30s%-10u%-10s"
        ,mPackIndex
        ,chw::getTimeStr("%Y-%m-%d %H:%M:%S",time_t(pcapHeader->ts.tv_sec)).c_str()
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

        if(_CMP_MEM_(iter->compare.c_str(), iter->compare.size(), buf + iter->start - 1, iter->compare.size()) == 0)
        {
            desc = iter->desc;
            break;
        }
        iter ++;
    }

    return desc;
}

// IP 协议解析
void PcapParse::ipDecode(const char* buf)
{
    int offset = 0;
    chw::IPHeader_t* ipHeader = (chw::IPHeader_t*)(buf + offset);
    offset += sizeof(chw::IPHeader_t);

    char srcIp[32] = { 0 };
    char dstIp[32] = { 0 };

    inet_ntop(AF_INET, &ipHeader->SrcIP, srcIp, sizeof(srcIp));
    inet_ntop(AF_INET, &ipHeader->DstIP, dstIp, sizeof(dstIp));

    uint16_t ipPackLen = ntohs(ipHeader->TotalLen);

    // if (0 != ipFilter(srcIp, dstIp))
    // {
    //     return;
    // }

    switch (ipHeader->Protocol)
    {
        case 17:// UDP协议
            // udpDecode(buf + offset, ipPackLen - sizeof(IPHeader_t));
            break;
        case 6: // TCP协议
            // tcpDecode(buf + offset, ipPackLen - sizeof(IPHeader_t));
            break;
        default:
            printf("[%s:%d]unsupported protocol %#x\n", __FILE__, __LINE__,
                   ipHeader->Protocol);
            break;
    }
}