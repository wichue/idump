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
    uint32_t Ipv4Decode(const char* buf, std::string& pro, std::string& des, std::string& src, chw::ayz_info& ayz);
    uint32_t Ipv6Decode(const char* buf, std::string& pro, std::string& des, std::string& src, chw::ayz_info& ayz);

    uint32_t UdpDecode(const char* buf, chw::ayz_info& ayz);
    uint32_t TcpDecode(const char* buf, uint16_t len, chw::ayz_info& ayz);
private:
    uint32_t mPackIndex;
};


#endif //__PCAP_PARSE_H
