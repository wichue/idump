#ifndef __PCAP_PARSE_H
#define __PCAP_PARSE_H

#include "ComProtocol.h"
#include <stddef.h>

class PcapParse {
public:
    PcapParse() = default;
    ~PcapParse() = default;

    void parse(const char* filename);
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
    void ipDecode(const char* buf);
private:
    uint32_t mPackIndex;
};


#endif //__PCAP_PARSE_H