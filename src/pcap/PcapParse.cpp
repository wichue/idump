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
    pcap_file_header* fileHeader = (pcap_file_header*)(buf + offset);
    offset += sizeof(pcap_file_header);
    PrintD("pcap file - magic:%#x version:%d.%d,snaplen:%u", fileHeader->magic, fileHeader->version_major, fileHeader->version_minor,fileHeader->snaplen);

    filtering(fileSize,offset,buf,fileHeader->snaplen);

    if (buf)
    {
        free(buf);
        buf = NULL;
    }
}

uint32_t PcapParse::filtering(size_t fileSize, size_t offset, char* buf, uint32_t snaplen)
{
    PrintD("No.       time                          len");

    size_t proto_offset = 0;
    mPackIndex = 0;
    while (offset < fileSize)
    {
        // pcap 包头
        pcap_pkthdr* pcapHeader = (pcap_pkthdr*)(buf + offset);
        proto_offset = offset + sizeof(pcap_pkthdr);

        offset += (pcapHeader->caplen + sizeof(pcap_pkthdr));
        mPackIndex++;
        
        // 以太头
        EthnetHeader_t* ethHeader = (EthnetHeader_t*)(buf + proto_offset);

        //输出日志
        PrintD("%-10u%-30s%-10u"
        ,mPackIndex
        ,chw::getTimeStr("%Y-%m-%d %H:%M:%S",time_t(pcapHeader->ts.tv_sec)).c_str()
        ,pcapHeader->caplen);

        if(gConfigCmd.more == true)
        {
            chw::PrintBuffer(buf + proto_offset,pcapHeader->caplen);
        }


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


    }

    PrintD("total package count:%d", mPackIndex);

    return 0;
}

// IP 协议解析
void PcapParse::ipDecode(const char* buf)
{
    int offset = 0;
    IPHeader_t* ipHeader = (IPHeader_t*)(buf + offset);
    offset += sizeof(IPHeader_t);

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