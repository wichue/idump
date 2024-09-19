#ifndef __PCAP_PARSE_H
#define __PCAP_PARSE_H

#include "ComProtocol.h"
#include <stddef.h>

class PcapParse {
public:
    PcapParse() = default;
    ~PcapParse() = default;

    void parse_file(const char* filename);
private:

    /**
     * @brief pcap逐帧解析
     * 
     * @param fileSize  pcap文件总的字节长度
     * @param offset    pcap头偏移
     * @param buf       pcap文件buf
     * @return uint32_t 
     */
    uint32_t resolve_each_frame(size_t fileSize, size_t offset, char* buf);

    std::string match_json(char* buf, size_t size);
    uint32_t Ipv4Decode(const char* buf, std::string& pro, std::string& des, std::string& src);
    uint32_t Ipv6Decode(const char* buf, std::string& pro, std::string& des, std::string& src);

    uint32_t UdpDecode(const char* buf);
    uint32_t TcpDecode(const char* buf, uint16_t len);
private:
    uint32_t mPackIndex;
};


#endif //__PCAP_PARSE_H
