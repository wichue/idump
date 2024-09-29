// Copyright (c) 2024 The idump project authors. SPDX-License-Identifier: MIT.
// This file is part of idump(https://github.com/wichue/idump).

#ifndef __PCAP_PARSE_H
#define __PCAP_PARSE_H

#include "ComProtocol.h"
#include <stddef.h>

namespace chw {

class PcapParse {
public:
    PcapParse();
    ~PcapParse();

    /**
     * @brief 解析pcap文件
     * 
     * @param filename	pcap文件路径
     */
    void parse_file(char* filename);
private:

    /**
     * @brief pcap逐帧解析
     * 
     * @param fileSize  [in]pcap文件总的字节长度
     * @param offset    [in]pcap偏移
     * @param buf       [in]pcap文件buf
     * @return uint32_t 成功返回chw::success,失败返回chw::fail
     */
    uint32_t resolve_each_frame(const char* filename, size_t fileSize, size_t offset, char* buf);

    /**
     * @brief 对每一帧匹配JSON文件读取的条件
     * 
     * @param buf   [in]帧buf
     * @param size  [in]帧长度
     * @param start [out]匹配成功的开始位置,用于输出显示颜色
     * @param end	[out]匹配成功的终止位置
     * @return std::string 匹配到的描述，没有匹配到则为空
     */
	std::string match_json(char* buf, size_t size, uint32_t& start, uint32_t& end);

    /**
     * @brief 对每一帧获取的信息，匹配命令行--filter过滤条件
     * 
     * @param ayz	[in]解析获取的帧信息
     * @return uint32_t 匹配成功返回chw::success,失败返回chw::fail
     */
	uint32_t match_filter(const chw::ayz_info& ayz);

    /**
     * @brief 依次为匹配frame、eth、IPV4、ipv6、arp、tcp、udp条件
     * 
     * @param ayz   [in]解析后的帧信息
     * @param cond  [in]过滤条件
     * @return uint32_t 成功返回chw::success,失败返回chw::fail
     */
	uint32_t match_frame(const chw::ayz_info& ayz, const chw::FilterCond& cond);
    uint32_t match_eth(const chw::ayz_info& ayz, const chw::FilterCond& cond);
    uint32_t match_ip(const chw::ayz_info& ayz, const chw::FilterCond& cond);
    uint32_t match_ipv6(const chw::ayz_info& ayz, const chw::FilterCond& cond);
    uint32_t match_arp(const chw::ayz_info& ayz, const chw::FilterCond& cond);
    uint32_t match_tcp(const chw::ayz_info& ayz, const chw::FilterCond& cond);
    uint32_t match_udp(const chw::ayz_info& ayz, const chw::FilterCond& cond);

    /**
     * @brief 解析IPV4
     * 
     * @param buf [in]IP头开始的buf
     * @param caplen [in]pcap捕获长度 - 以太头长度，理论上IP头和负载的总长度
     * @param pro [out]协议类型，用于输出到日志
     * @param des [out]目的地址，用于输出到日志
     * @param src [out]源地址，用于输出到日志
     * @param ayz [out]解析的信息
     * @return uint32_t 成功返回chw::success,失败返回chw::fail
     */
    uint32_t Ipv4Decode(const char* buf, uint32_t len, std::string& pro, std::string& des, std::string& src, chw::ayz_info& ayz);
    
    /**
     * @brief 解析IPV6
     * 
     * @param buf [in]IP头开始的buf
     * @param caplen [in]pcap捕获长度 - 以太头长度，理论上IP头和负载的总长度
     * @param pro [out]协议类型，用于输出到日志
     * @param des [out]目的地址，用于输出到日志
     * @param src [out]源地址，用于输出到日志
     * @param ayz [out]解析的信息
     * @return uint32_t 成功返回chw::success,失败返回chw::fail
     */
    uint32_t Ipv6Decode(const char* buf, uint32_t caplen, std::string& pro, std::string& des, std::string& src, chw::ayz_info& ayz);

    /**
     * @brief 解析udp
     * 
     * @param buf       [in]ip负载buf
     * @param caplen    [in]ip负载，即udp头和udp负载总长度
     * @param ayz       [out]解析的信息
     * @return uint32_t 成功返回chw::success,失败返回chw::fail
     */
    uint32_t UdpDecode(const char* buf, uint16_t caplen, chw::ayz_info& ayz);
    
    /**
     * @brief 解析udp
     * 
     * @param buf       [in]ip负载buf
     * @param caplen    [in]ip负载，即tcp头和tcp负载总长度
     * @param ayz       [out]解析的信息
     * @return uint32_t 成功返回chw::success,失败返回chw::fail
     */
    uint32_t TcpDecode(const char* buf, uint16_t caplen, chw::ayz_info& ayz);
private:
    uint32_t mPackIndex;	// 帧序号

    char* _filename;		// pcap文件路径
    char* _buf;				// 存储文件的buf
    size_t _fileSize;		// 文件大小
public:
    chw::ComMatchBuf _cmpbuf;// 比对信息
};

}// namespace chw
#endif //__PCAP_PARSE_H
