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

void PcapParse::parse_file(const char* filename)
{
    struct stat st;
    if (stat(filename, &st))
    {
        PrintD("stat file %s failed, errno=%d errmsg=%s\n", filename, errno, strerror(errno));
        return;
    }

    size_t fileSize = st.st_size;

    if (!fileSize)
    {
        PrintD("file is empty!\n");
        return;
    }

    char *buf = (char*)malloc(fileSize + 1);

    FILE* fp = fopen(filename, "r");
    if (!fp)
    {
        PrintD("open file %s failed, errno=%d errmsg=%s\n", filename, errno, strerror(errno));
        return;
    }
    fread(buf, sizeof(char), fileSize, fp);
    fclose(fp);


    size_t offset = 0;
    // pcap 文件头
    chw::pcap_file_header* fileHeader = (chw::pcap_file_header*)(buf + offset);
    offset += sizeof(chw::pcap_file_header);
    PrintD("pcap file - magic:%#x version:%d.%d,snaplen:%u", fileHeader->magic, fileHeader->version_major, fileHeader->version_minor,fileHeader->snaplen);

    resolve_each_frame(fileSize,offset,buf);

    if (buf)
    {
        free(buf);
        buf = NULL;
    }
}

/**
 * @brief pcap逐帧解析
 * 
 * @param fileSize  pcap文件总的字节长度
 * @param offset    pcap偏移
 * @param buf       pcap文件buf
 * @return uint32_t 
 */
uint32_t PcapParse::resolve_each_frame(size_t fileSize, size_t offset, char* buf)
{
    PrintD("No.     time                    Source                          Destination                     protocol  len     desc      ");

    size_t proto_offset = 0;//以太头偏移
    mPackIndex = 0;//抓包帧序号
    while (offset < fileSize)
    {
		//1.解析pcap帧头
        if(fileSize - offset < sizeof(chw::pcap_pkthdr))
        {
            PrintD("error pcap_pkthdr len, unexpected fileSize=%lu,offset=%lu", fileSize, offset);
            break;
        }
        mPackIndex++;

        chw::ayz_info ayz;
        // pcap头
        chw::pcap_pkthdr* pcapHeader = (chw::pcap_pkthdr*)(buf + offset);
        proto_offset = offset + sizeof(chw::pcap_pkthdr);
        ayz.pcap = pcapHeader;
        
        //2.匹配json过滤条件
        if(fileSize - offset - sizeof(chw::pcap_pkthdr) < pcapHeader->caplen)
        {
            PrintD("error caplen, unexpected fileSize=%lu,offset=%lu,caplen=%u", fileSize, offset,pcapHeader->caplen);
            break;
        }
        std::string desc = match_json(buf + proto_offset, pcapHeader->caplen);
        if(desc.size() == 0)
        {
            continue;
        }

		//3.解析以太头
		if(fileSize - offset - sizeof(chw::pcap_pkthdr) < sizeof(chw::ethhdr))
		{
			PrintD("error ethhdr len, unexpected fileSize=%lu,offset=%lu", fileSize, offset);
			break;
		}
		offset += (pcapHeader->caplen + sizeof(chw::pcap_pkthdr));

        // 以太头
        chw::ethhdr* ethHeader = (chw::ethhdr*)(buf + proto_offset);
        uint16_t protocol = ntohs(ethHeader->h_proto);
        ayz.eth = ethHeader;

        // 协议类型，如果是ipv4或ipv6，且是已知的tcp/udp等传输层协议，则显示传输层协议，如果是未知的则显示16进制值
        std::string str_Protocol = chw::HexBuftoString((const unsigned char*)&ethHeader->h_proto,2);//0800,86dd
        // ipv4和ipv6显示目的IP地址，其他显示目的MAC地址
        std::string str_Destination = chw::MacBuftoStr((const unsigned char*)(ethHeader->h_dest));
        // ipv4和ipv6显示源IP地址，其他显示源MAC地址
        std::string str_Source = chw::MacBuftoStr((const unsigned char*)(ethHeader->h_source));

        // ip 协议
        switch(protocol)
        {
            case 0x0800:
                str_Protocol = "ipv4";
                ayz.ipver = chw::IPV4;
                Ipv4Decode(buf + proto_offset + sizeof(chw::ethhdr), pcapHeader->caplen - sizeof(chw::ethhdr), str_Protocol, str_Destination, str_Source, ayz);
                break;
            case 0x86dd:
                str_Protocol = "ipv6";
                ayz.ipver = chw::IPV6;
                Ipv6Decode(buf + proto_offset + sizeof(chw::ethhdr), pcapHeader->caplen - sizeof(chw::ethhdr), str_Protocol, str_Destination, str_Source, ayz);
    	        break;
			case 0x0806:
				str_Protocol = "ARP";
				break;
			case 0x8864:
				str_Protocol = "PPPoE";
				break;
			case 0x8847:
				str_Protocol = "MPLS-TP";
				break;
			case 0x8848:
				str_Protocol = "MPLS";
				break;
			case 0x8100:
				str_Protocol = "802.1Q";
				break;

            // 其他自定义协议
            default:
            break;
        }

        //4.匹配命令行filter条件
        if(match_filter(ayz) == chw::fail)
        {
            continue;
        }


        //输出日志
        //No.       time                          Source          Destination     protocol  len       desc      
        PrintD("%-8u%-24s%-32s%-32s%-10s%-8u%-10s"
        ,mPackIndex
        ,chw::getTimeStr("%Y-%m-%d %H:%M:%S",time_t(pcapHeader->ts.tv_sec)).c_str()
        ,str_Source.c_str()
        ,str_Destination.c_str()
        ,str_Protocol.c_str()
        ,pcapHeader->caplen
        ,desc.c_str());

        if(gConfigCmd.max > 0)
        {
            chw::PrintBuffer(buf + proto_offset, pcapHeader->caplen);
        }
    }

    PrintD("total package count:%d", mPackIndex);

    return chw::success;
}

/**
 * @brief 对每一帧匹配JSON文件读取的条件
 * 
 * @param buf   帧buf
 * @param size  帧长度
 * @return std::string 匹配到的描述，没有匹配到则为空
 */
std::string PcapParse::match_json(char* buf, size_t size)
{
    std::string desc = "";
    auto iter = g_vCondJson.begin();
    while(iter != g_vCondJson.end())
    {
        if(iter->start >= size)
        {
            continue;
        }

        if(iter->start + iter->compare.size() -1 > size)
        {
            continue;
        }

        if(iter->compare.size() == 0)
        {
            continue;
        }

        //todo:匹配通配符
        if(_CMP_MEM_(iter->compare.c_str(), iter->compare.size(), buf + iter->start - 1, iter->compare.size()) == 0)
        {
            desc = iter->desc;
            break;
        }
        iter ++;
    }

    return desc;
}
/*
// 条件表达式
//demo:
//tcp.dstport == 80	# desc
//==				# op
//tcp.dstport		# exp_front
//80 				# exp_back
//tcp 				# protol
//dstport 			# po_value
struct FilterCond {
    bool bValid = false;// 是否有效的条件
    and_or ao;// 与上一个FilterCond是 && 还是 || 关系

    std::string desc;// 来自命令行的原始条件表达式
    _operator op;// 比较运算符
    std::string exp_front;// 比较运算符前面的表达式
    std::string exp_back;// 比较运算符后面的表达式
    bool non = false;// 最前面是否包含 ! 运算符，最多只能有一个!运算符，不像wireshark可以嵌套多个

    _protocol potol;// 协议类型
    uint16_t option_val;// 协议的参数选项
};
// 条件表达式的协议类型
enum _protocol {
    _frame, //frame
    _eth,   //eth
    _ip,    //ip
    _arp,   //arp
    _tcp,   //tcp
    _udp,   //udp
};*/
uint32_t PcapParse::match_filter(chw::ayz_info& ayz)
{
	for(size_t index=0;index<g_vCondFilter.size();index++)
	{
		if(g_vCondFilter[index].bValid == false)
		{
			continue;
		}
		uint32_t match_ret = chw::fail;
		switch(g_vCondFilter[index].potol)
		{
		case chw::_frame:
			match_ret = match_frame(ayz,g_vCondFilter[index]);
			break;
        case chw::_eth:
			match_ret = match_eth(ayz,g_vCondFilter[index]);
			break;
		}


	}
}

/**
 * @brief 计算条件表达式的值
 * 
 * @param ayz_len   解析pcap得到的长度
 * @param cond_len  匹配条件的长度
 * @return uint32_t 匹配成功返回chw::success,失败返回chw::fail
 */
uint32_t CompareOpt(uint32_t ayz_len, uint32_t cond_len, chw::_operator op)
{
    switch(op)
    {
    case chw::_EQUAL:             // ==
        return ayz_len == cond_len ? chw::success : chw::fail;
    case chw::_GREATER:           // >
        return ayz_len > cond_len ? chw::success : chw::fail;
    case chw::_GREATER_EQUAL:     // >=
        return ayz_len >= cond_len ? chw::success : chw::fail;
    case chw::_LESS:              // <
        return ayz_len < cond_len ? chw::success : chw::fail;
    case chw::_LESS_EQUAL:        // <=
        return ayz_len <= cond_len ? chw::success : chw::fail;

        default:
        break;
    }

    return chw::fail;
}

/**
 * @brief 匹配frame条件
 * 
 * @param ayz   解析后的帧信息
 * @param cond  过滤条件
 * @return uint32_t 成功返回chw::success,失败返回chw::fail
 */
uint32_t PcapParse::match_frame(const chw::ayz_info& ayz, const chw::FilterCond& cond)
{
	if(ayz.pcap == nullptr)
	{
		return chw::fail;
	}

    //如果后置表达式为空，则返回成功，因为满足这是一个帧的条件，类似wireshark的判断
    if(cond.exp_back.size() == 0)
    {
        return chw::success;
    }

	uint32_t len = 0;
    try {
		len = std::stoi(cond.exp_back.c_str());
	} catch (std::exception& ex) {
		PrintD("error: failed string to int,exp_back=%s",cond.exp_back.c_str());
	}
	switch(cond.option_val)
	{
	case chw::frame_len:
        return CompareOpt(ayz.pcap->len, len, cond.op);
	case chw::frame_cap_len:
        return CompareOpt(ayz.pcap->caplen, len, cond.op);

	default:
		break;
	}

	return chw::fail;
}

uint32_t PcapParse::match_eth(const chw::ayz_info& ayz, const chw::FilterCond& cond)
{
	if(ayz.eth == nullptr)
	{
		return chw::fail;
	}

    switch(cond.option_val)
	{
	case chw::eth_dst:
	case chw::eth_src:
    case chw::eth_type:

	default:
		break;
	}

	return chw::fail;
}

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
uint32_t PcapParse::Ipv4Decode(const char* buf, uint32_t caplen, std::string& pro, std::string& des, std::string& src, chw::ayz_info& ayz)
{
    //1.捕获长度小于最小ip头长度
    if(caplen < sizeof(chw::ip4hdr))
    {
        PrintD("error: ip4 caplen too small, caplen=%lu", caplen);
        return chw::fail;
    }
    chw::ip4hdr* ipHeader = (chw::ip4hdr*)(buf);
	ayz.ip4 = ipHeader;

    std::string srcIp = chw::sockaddr_ipv4(ipHeader->saddr);
    std::string dstIp = chw::sockaddr_ipv4(ipHeader->daddr);

    srcIp.size() == 0 ? 0 :src = srcIp;
    dstIp.size() == 0 ? 0 :des = dstIp;

    uint16_t toal_len = ntohs(ipHeader->tot_len);// IP头+后面负载总长度
    uint16_t head_len  = ipHeader->ihl * 4;// ip头长度
    //2.错误的头长度
    if(head_len > toal_len)
    {
        PrintD("error: ip4 head_len=%lu,toal_len=%lu",head_len, toal_len);
        return chw::fail;
    }

    //3.捕获长度小于ip头解析的总长度
    if(caplen < toal_len)
    {
        PrintD("error: Incomplete ip4 package, caplen=%lu,toal_len=%lu", caplen, toal_len);
        return chw::fail;
    }

    //4.捕获长度大于ip头解析的总长度，继续解析
    if(caplen > toal_len)
    {
        PrintD("warn: too big ip4 caplen=%lu,toal_len=%lu", caplen, toal_len);
    }

    switch (ipHeader->protocol)
    {
        case 17:// UDP协议
            pro = "udp";
            return UdpDecode(buf + head_len, toal_len - head_len, ayz);
        case 6: // TCP协议
            pro = "tcp";
            return TcpDecode(buf + head_len, toal_len - head_len, ayz);
        default:
            // 其他协议，待补充
            break;
    }

	return chw::fail;
}

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
uint32_t PcapParse::Ipv6Decode(const char* buf, uint32_t caplen, std::string& pro, std::string& des, std::string& src, chw::ayz_info& ayz)
{
    //1.捕获长度小于最小ip头长度
    if(caplen < sizeof(chw::ip6hdr))
    {
        PrintD("error: ip6 caplen too small, caplen=%lu", caplen);
        return chw::fail;
    }

    chw::ip6hdr* ipHeader = (chw::ip6hdr*)(buf);

    std::string srcIp = chw::sockaddr_ipv6(ipHeader->saddr);
    std::string dstIp = chw::sockaddr_ipv6(ipHeader->daddr);

    srcIp.size() == 0 ? 0 :src = srcIp;
    dstIp.size() == 0 ? 0 :des = dstIp;

    uint16_t load_len = ntohs(ipHeader->payload_len);// 后面负载总长度
    uint16_t head_len  = sizeof(chw::ip6hdr);// ip头长度

    uint16_t toal_len = load_len + head_len;

    //2.捕获长度小于ip头解析的总长度
    if(caplen < toal_len)
    {
        PrintD("error: Incomplete ip6 package, caplen=%lu,toal_len=%lu", caplen, toal_len);
        return chw::fail;
    }

    //3.捕获长度大于ip头解析的总长度，继续解析
    if(caplen > toal_len)
    {
        PrintD("warn: too big ip6 caplen=%lu,toal_len=%lu", caplen, toal_len);
    }

    // todo:匹配ip过滤条件
    switch (ipHeader->nexthdr)
    {
        case 17:// UDP协议
            pro = "udp";
            return UdpDecode(buf + head_len, load_len, ayz);
        case 6: // TCP协议
            pro = "tcp";
            return TcpDecode(buf + head_len, load_len, ayz);
        default:
            // 其他协议，待补充
            break;
    }

	return chw::fail;
}

/**
 * @brief 解析udp
 * 
 * @param buf       [in]ip负载buf
 * @param caplen    [in]ip负载，即udp头和udp负载总长度
 * @param ayz       [out]解析的信息
 * @return uint32_t 成功返回chw::success,失败返回chw::fail
 */
uint32_t PcapParse::UdpDecode(const char* buf, uint16_t caplen, chw::ayz_info& ayz)
{
    if(caplen < sizeof(chw::udphdr))
    {
        PrintD("error: too small udp caplen=%lu", caplen);
        return chw::fail;
    }

    ayz.transport = chw::udp_trans;
	ayz.udp = (chw::udphdr*)(buf);

    // chw::udphdr* udpHeader = (chw::udphdr*)(buf);
    if(ayz.udp->len != caplen)
    {
        PrintD("error: no match udp caplen=%lu,ayz udp len=%lu", caplen,ayz.udp->len);
        return chw::fail;
    }

    // uint16_t srcPort = ntohs(udpHeader->source);
    // uint16_t dstPort = ntohs(udpHeader->dest);
    // // udp负载长度
    // uint16_t loadLen = ntohs(udpHeader->len) - sizeof(chw::udphdr);

    return chw::success;
}


/**
 * @brief 解析udp
 * 
 * @param buf       [in]ip负载buf
 * @param caplen    [in]ip负载，即tcp头和tcp负载总长度
 * @param ayz       [out]解析的信息
 * @return uint32_t 成功返回chw::success,失败返回chw::fail
 */
uint32_t PcapParse::TcpDecode(const char* buf, uint16_t caplen, chw::ayz_info& ayz)
{
    if(caplen < sizeof(chw::tcphdr))
    {
        PrintD("error: too small tcp caplen=%lu", caplen);
        return chw::fail;
    }

    ayz.transport = chw::tcp_trans;
    ayz.tcp = (chw::tcphdr*)(buf);

    uint16_t head_len = ayz.tcp->doff * 4;
    if(caplen < head_len)
    {
        PrintD("error: no match tcp caplen=%lu,head_len=%lu", caplen,head_len);
        return chw::fail;
    }

    return chw::success;

    // chw::tcphdr* tcpHeader = (chw::tcphdr*)(buf);

    // uint16_t srcPort = ntohs(tcpHeader->source);
    // uint16_t dstPort = ntohs(tcpHeader->dest);
    // // tcp负载长度
    // uint16_t loadLen = caplen - tcpHeader->doff * 4;

    // todo:匹配tcp过滤条件

    // PrintD("tcp srcPort=%d,dstPort=%d,loadLen=%u",srcPort,dstPort,loadLen);
}
