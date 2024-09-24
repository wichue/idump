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
	uint32_t match_index = 0;
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
        std::string desc = "";
        if(g_vCondJson.size() > 0)
        {
            desc = match_json(buf + proto_offset, pcapHeader->caplen);
            if(desc.size() == 0)
            {
                offset += (pcapHeader->caplen + sizeof(chw::pcap_pkthdr));
                continue;
            }
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
                Ipv4Decode(buf + proto_offset + sizeof(chw::ethhdr), pcapHeader->caplen - (uint32_t)sizeof(chw::ethhdr), str_Protocol, str_Destination, str_Source, ayz);
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
		match_index ++;


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

	PrintD("total package count:%u", mPackIndex);
    PrintD("match package count:%u", match_index);

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

uint32_t PcapParse::match_filter(chw::ayz_info& ayz)
{
    if(g_vCondFilter.size() == 0)
    {
        return chw::success;
    }

    uint32_t last_match = chw::fail;
	for(size_t index=0;index<g_vCondFilter.size();index++)
	{
		uint32_t match_ret = chw::fail;
		switch(g_vCondFilter[index].potol)
		{
		case chw::_frame:
			match_ret = match_frame(ayz,g_vCondFilter[index]);
			break;
        case chw::_eth:
			match_ret = match_eth(ayz,g_vCondFilter[index]);
			break;
        case chw::_ip:
			match_ret = match_ip(ayz,g_vCondFilter[index]);
			break;
        case chw::_ipv6:
			match_ret = match_ipv6(ayz,g_vCondFilter[index]);
			break;
        case chw::_arp:
            match_ret = match_arp(ayz,g_vCondFilter[index]);
            break;
        case chw::_tcp:
            match_ret = match_tcp(ayz,g_vCondFilter[index]);
            break;
        case chw::_udp:
            match_ret = match_udp(ayz,g_vCondFilter[index]);
            break;

        default:
            PrintD("error: unknown protocol = %d", g_vCondFilter[index].potol);
            return chw::fail;
		}

        if(g_vCondFilter[index].non == true)
        {
            if(match_ret == chw::fail)
			{
				match_ret = chw::success;
			}
			else
			{
				match_ret = chw::fail;
			}
        }

        switch(g_vCondFilter[index].ao)
        {
            case chw::_and:
            //前一个条件和当前条件有一个是false，则返回失败
            if(last_match == chw::fail || match_ret == chw::fail)
            {
                return chw::fail;
            }
			else
			{
				if(index == g_vCondFilter.size() - 1)
				{
					return chw::success;
				}
			}
            break;
            case chw::_or:
            //前一个条件和当前条件都是false，则返回失败
			if(index != 0)
			{
           		if(last_match == chw::fail && match_ret == chw::fail)
	            {
    	            return chw::fail;
        	    }
			else
			{
				if(index == g_vCondFilter.size() - 1)
				{
					return chw::success;
				}
			}
			}
            break;
            case chw::_null:

            default:
            break;
        }
        last_match = match_ret;
	}

    return last_match;
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
    case chw::_UNEQUAL:           // !=
        return ayz_len != cond_len ? chw::success : chw::fail;
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

	switch(cond.option_val)
	{
	case chw::frame_len:
        return CompareOpt(ayz.pcap->len, cond.int_comm, cond.op);
	case chw::frame_cap_len:
        return CompareOpt(ayz.pcap->caplen, cond.int_comm, cond.op);

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

    if(cond.exp_back.size() == 0)
    {
        return chw::success;
    }

    switch(cond.option_val)
	{
	case chw::eth_dst:
        if(_CMP_MEM_(ayz.eth->h_dest,ETH_ALEN,cond.mac,ETH_ALEN) == 0)
        {
            return chw::success;
        }
        break;
	case chw::eth_src:
        if(_CMP_MEM_(ayz.eth->h_source,ETH_ALEN,cond.mac,ETH_ALEN) == 0)
        {
            return chw::success;
        }
        break;
    case chw::eth_type:
        return CompareOpt(ayz.eth->h_proto, cond.int_comm, cond.op);

	default:
		break;
	}

	return chw::fail;
}

uint32_t PcapParse::match_ip(const chw::ayz_info& ayz, const chw::FilterCond& cond)
{
	if(ayz.ip4 == nullptr)
	{
		return chw::fail;
	}

    if(ayz.ipver != chw::IPV4)
    {
        return chw::fail;
    }

    if(cond.exp_back.size() == 0)
    {
        return chw::success;
    }

    switch(cond.option_val)
	{
	case chw::ip_hdr_len:
        return CompareOpt(ayz.ip4->ihl * 4, cond.int_comm, cond.op);
	case chw::ip_version:
        return CompareOpt(ayz.ip4->version, cond.int_comm, cond.op);
    case chw::ip_tos:
        return CompareOpt(ayz.ip4->tos, cond.int_comm, cond.op);
    case chw::ip_len:
        return CompareOpt(ntohs(ayz.ip4->tot_len), cond.int_comm, cond.op);
	case chw::ip_id:
        return CompareOpt(ayz.ip4->id, cond.int_comm, cond.op);
    case chw::ip_fragment:
        return CompareOpt(ayz.ip4->frag_off, cond.int_comm, cond.op);
	case chw::ip_ttl:
        return CompareOpt(ayz.ip4->ttl, cond.int_comm, cond.op);
    case chw::ip_proto:
        return CompareOpt(ayz.ip4->protocol, cond.int_comm, cond.op);
	case chw::ip_checksum:
        return CompareOpt(ayz.ip4->check, cond.int_comm, cond.op);
    case chw::ip_src_host:
        if(ayz.ip4->saddr == cond.ipv4.s_addr)
        {
            return chw::success;
        }
        break;
	case chw::ip_dst_host:
        if(ayz.ip4->daddr == cond.ipv4.s_addr)
        {
            return chw::success;
        }
        break;

	default:
		break;
	}

	return chw::fail;
}

uint32_t PcapParse::match_ipv6(const chw::ayz_info& ayz, const chw::FilterCond& cond)
{
	if(ayz.ip6 == nullptr)
	{
		return chw::fail;
	}

    if(ayz.ipver != chw::IPV6)
    {
        return chw::fail;
    }

    if(cond.exp_back.size() == 0)
    {
        return chw::success;
    }

	uint32_t ver = 0;
    switch(cond.option_val)
	{
	case chw::ipv6_version://demo:60 09 fa 93
		ver = (uint32_t)chw::int16_highfour(ntohs(*(int16_t*)ayz.ip6));
        return CompareOpt(ver, cond.int_comm, cond.op);
   // case chw::ipv6_flow:
   //     return CompareOpt(ayz.ip6->flow_lbl, cond.int_comm, cond.op);
    case chw::ipv6_plen:
        return CompareOpt(ntohs(ayz.ip6->payload_len), cond.int_comm, cond.op);
	case chw::ipv6_nxt:
        return CompareOpt(ayz.ip6->nexthdr, cond.int_comm, cond.op);
    case chw::ipv6_src_host:
        if(_CMP_MEM_(&ayz.ip6->saddr,sizeof(struct in6_addr),&cond.ipv6,sizeof(struct in6_addr)) == 0)
        {
            return chw::success;
        }
        break;
	case chw::ipv6_dst_host:
        if(_CMP_MEM_(&ayz.ip6->daddr,sizeof(struct in6_addr),&cond.ipv6,sizeof(struct in6_addr)) == 0)
        {
            return chw::success;
        }
        break;

	default:
		break;
	}

	return chw::fail;
}

uint32_t PcapParse::match_arp(const chw::ayz_info& ayz, const chw::FilterCond& cond)
{
    //todo
    return chw::fail;
}

uint32_t PcapParse::match_tcp(const chw::ayz_info& ayz, const chw::FilterCond& cond)
{
	if(ayz.tcp == nullptr)
	{
		return chw::fail;
	}

    if(ayz.transport != chw::tcp_trans)
    {
        return chw::fail;
    }

    if(cond.exp_back.size() == 0)
    {
        return chw::success;
    }

    switch(cond.option_val)
	{
	case chw::tcp_hdr_len:
        return CompareOpt(ayz.tcp->doff * 4, cond.int_comm, cond.op);
    case chw::tcp_srcport:
        return CompareOpt(ntohs(ayz.tcp->source), cond.int_comm, cond.op);
    case chw::tcp_dstport:
        return CompareOpt(ntohs(ayz.tcp->dest), cond.int_comm, cond.op);
    case chw::tcp_seq:
        return CompareOpt(ayz.tcp->seq, cond.int_comm, cond.op);
    case chw::tcp_ack:
        return CompareOpt(ayz.tcp->ack_seq, cond.int_comm, cond.op);
    case chw::tcp_fin:
        return CompareOpt(ayz.tcp->fin, cond.int_comm, cond.op);
    case chw::tcp_syn:
        return CompareOpt(ayz.tcp->syn, cond.int_comm, cond.op);
    case chw::tcp_reset:
        return CompareOpt(ayz.tcp->rst, cond.int_comm, cond.op);
    case chw::tcp_push:
        return CompareOpt(ayz.tcp->psh, cond.int_comm, cond.op);
    case chw::tcp_ack_flag:
        return CompareOpt(ayz.tcp->ack, cond.int_comm, cond.op);
    case chw::tcp_urg:
        return CompareOpt(ayz.tcp->urg, cond.int_comm, cond.op);
    case chw::tcp_ece:
        return CompareOpt(ayz.tcp->ece, cond.int_comm, cond.op);
    case chw::tcp_cwr:
        return CompareOpt(ayz.tcp->cwr, cond.int_comm, cond.op);
    case chw::tcp_window_size:
        return CompareOpt(ntohs(ayz.tcp->window), cond.int_comm, cond.op);
    case chw::tcp_checksum:
        return CompareOpt(ayz.tcp->check, cond.int_comm, cond.op);
    case chw::tcp_urgent_pointer:
        return CompareOpt(ayz.tcp->urg_ptr, cond.int_comm, cond.op);

	default:
		break;
	}

	return chw::fail;
}

uint32_t PcapParse::match_udp(const chw::ayz_info& ayz, const chw::FilterCond& cond)
{
    if(ayz.udp == nullptr)
	{
		return chw::fail;
	}

    if(ayz.transport != chw::udp_trans)
    {
        return chw::fail;
    }

    if(cond.exp_back.size() == 0)
    {
        return chw::success;
    }

    switch(cond.option_val)
	{
	case chw::udp_srcport:
        return CompareOpt(ntohs(ayz.udp->source), cond.int_comm, cond.op);
	case chw::udp_dstport:
        return CompareOpt(ntohs(ayz.udp->dest), cond.int_comm, cond.op);
    case chw::udp_length:
        return CompareOpt(ntohs(ayz.udp->len), cond.int_comm, cond.op);
    case chw::udp_checksum:
        return CompareOpt(ayz.udp->check, cond.int_comm, cond.op);

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
    if(caplen < (uint32_t)sizeof(chw::ip4hdr))
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
        PrintD("error: Incomplete ip4 package, caplen=%u,toal_len=%u", caplen, toal_len);
        return chw::fail;
    }

    //4.捕获长度大于ip头解析的总长度，继续解析
    if(caplen > toal_len)
    {
        //当原始数据不足60时网卡会自动补0，出现 caplen > toal_len 的情况
        // PrintD("warn: too big ip4 caplen=%u,toal_len=%u", caplen, toal_len);
    }

    switch (ipHeader->protocol)
    {
        case 17:// UDP协议
            pro = "udp";
            return UdpDecode(buf + head_len, toal_len - head_len, ayz);
        case 6: // TCP协议
            pro = "tcp";
            return TcpDecode(buf + head_len, toal_len - head_len, ayz);
		case 1: // ICMP
			pro = "ICMP";
			break;
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
    ayz.ip6 = ipHeader;

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
		case 1: // ICMP
			pro = "ICMP";
			break;
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
    if(ntohs(ayz.udp->len) != caplen)
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
