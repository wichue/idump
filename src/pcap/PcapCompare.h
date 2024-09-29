// Copyright (c) 2024 The idump project authors. SPDX-License-Identifier: MIT.
// This file is part of idump(https://github.com/wichue/idump).
/*
IP=192.168.1.100
Mask=255.255.255.0
Gateway=192.168.1.1
DNS=192.168.1.1
MAC=d3:56:fa:a2:e0:05
*/
#ifndef __PCAP_COMPARE_H
#define __PCAP_COMPARE_H

#include "util.h"
#include "ComProtocol.h"

namespace chw {
class PcapCompare {
public: 
	PcapCompare() = default;
	~PcapCompare() = default;

    static PcapCompare &Instance();

	/**
	 * @brief 按字节比对两个pcap文件
	 * 
	 */
	void CompareFile();
};

}// namespace chw
#endif // __PCAP_COMPARE_H
