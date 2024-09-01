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
    uint32_t filtering(size_t fileSize, size_t offset, char* buf, uint32_t snaplen);
    void ipDecode(const char* buf);
private:
    uint32_t mPackIndex;
};


#endif //__PCAP_PARSE_H