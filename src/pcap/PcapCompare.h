// Copyright (c) 2024 The idump project authors. SPDX-License-Identifier: MIT.
// This file is part of idump(https://github.com/wichue/idump).

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
