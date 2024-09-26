#ifndef __PCAP_COMPARE_H
#define __PCAP_COMPARE_H

#include "util.h"
#include "ComProtocol.h"

class PcapCompare {
public: 
	PcapCompare() = default;
	~PcapCompare() = default;

    static PcapCompare &Instance();
	void CompareFile();
private:
	chw::ComMatchBuf _buffer1;
	chw::ComMatchBuf _buffer2;
};

#endif // __PCAP_COMPARE_H
