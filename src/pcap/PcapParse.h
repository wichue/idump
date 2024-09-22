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
     * @param offset    pcap偏移
     * @param buf       pcap文件buf
     * @return uint32_t 成功返回chw::success,失败返回chw::fail
     */
    uint32_t resolve_each_frame(size_t fileSize, size_t offset, char* buf);

    /**
     * @brief 对每一帧匹配JSON文件读取的条件
     * 
     * @param buf   帧buf
     * @param size  帧长度
     * @return std::string 匹配到的描述，没有匹配到则为空
     */
    std::string match_json(char* buf, size_t size);
	uint32_t match_filter(chw::ayz_info& ayz);

    /**
     * @brief 匹配frame条件
     * 
     * @param ayz   解析后的帧信息
     * @param cond  过滤条件
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
    uint32_t mPackIndex;
};


#endif //__PCAP_PARSE_H
