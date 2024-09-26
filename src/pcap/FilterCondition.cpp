#include "FilterCondition.h"
#include <string>
#include <vector>
#include "util.h"
#include "Logger.h"
#include "GlobalValue.h"
#include "MemoryHandle.h"

void FilterCondition::ParseFilter(char* filter)
{
    std::string filter_trim = chw::replaceAll(filter," ","");
    PrintD("filter_trim=%s",filter_trim.c_str());

    //1.解析与或条件
    std::vector<std::string> msg_or = chw::split(filter_trim,"||");
    auto iter_or = msg_or.begin();
    while(iter_or != msg_or.end())
    {
        std::vector<std::string> msg_and = chw::split(*iter_or,"&&");
        int index=0;
        auto iter_and = msg_and.begin();
        while(iter_and != msg_and.end())
        {
            chw::FilterCond tcond;
            tcond.desc = *iter_and;
            if(index == 0)
            {
                tcond.ao = chw::_or;
            }
            else
            {
                tcond.ao = chw::_and;
            }
            g_vCondFilter.push_back(tcond);
            index++;
            iter_and++;
        }
        iter_or++;
    }

    //2.解析比较运算符
    auto iter_cond = g_vCondFilter.begin();
    while(iter_cond != g_vCondFilter.end())
    {
        std::vector<std::string> list;
        do {
            list = chw::split(iter_cond->desc,"==");
            if( list.size() == 2)
            {
                iter_cond->exp_front = list[0];
                iter_cond->exp_back = list[1];
                iter_cond->op = chw::_EQUAL;
                break;
            }

            list = chw::split(iter_cond->desc,"!=");
            if( list.size() == 2)
            {
                iter_cond->exp_front = list[0];
                iter_cond->exp_back = list[1];
                iter_cond->op = chw::_UNEQUAL;
                break;
            }

            list = chw::split(iter_cond->desc,">=");
            if( list.size() == 2)
            {
                iter_cond->exp_front = list[0];
                iter_cond->exp_back = list[1];
                iter_cond->op = chw::_GREATER_EQUAL;
                break;
            }

            list = chw::split(iter_cond->desc,">");
            if( list.size() == 2)
            {
                iter_cond->exp_front = list[0];
                iter_cond->exp_back = list[1];
                iter_cond->op = chw::_GREATER;
                break;
            }

            list = chw::split(iter_cond->desc,"<=");
            if( list.size() == 2)
            {
                iter_cond->exp_front = list[0];
                iter_cond->exp_back = list[1];
                iter_cond->op = chw::_LESS_EQUAL;
                break;
            }

            list = chw::split(iter_cond->desc,"<");
            if( list.size() == 2)
            {
                iter_cond->exp_front = list[0];
                iter_cond->exp_back = list[1];
                iter_cond->op = chw::_LESS;
                break;
            }
        } while(0);

		if(list.size() == 1)
		{
			iter_cond->exp_front = list[0];
		}

        if(list.size() > 0)
        {
            //3.解析单个条件表达式
            if(ParseFrontExp(*iter_cond) == chw::success)
			{
				iter_cond++;
			}
			else
			{
				exit(1);
				//iter_cond = g_vCondFilter.erase(iter_cond);
			}
        }
        else
        {
            PrintD("unknown operator,desc=%s",iter_cond->desc.c_str());
            iter_cond = g_vCondFilter.erase(iter_cond);
			exit(1);
        }
    }

}

uint32_t FilterCondition::exp_back2int(chw::FilterCond& cond)
{
	if(cond.exp_back.size() > 0)
	{
		/*
		try {
			cond.int_comm = std::stoi(cond.exp_back);
		} catch (const std::exception& ex) {
			PrintD("error: failed string to int,exp_back=%s",cond.exp_back.c_str());
			return chw::fail;
		}
		*/
		cond.int_comm = chw::String2Num<uint32_t>(cond.exp_back);	
	}

	return chw::success;
}

/**
 * @brief ipv4地址转换为32位网络字节序
 * 
 * @param cond 条件表达式
 * @return uint32_t 转换成功或exp_back长度为0返回chw::success，否则返回chw::fail
 */
uint32_t FilterCondition::exp_back2ipv4(chw::FilterCond& cond)
{
	if(cond.exp_back.size() > 0)
	{
		_RAM_SET_(&cond.ipv4,sizeof(struct in_addr),0,sizeof(struct in_addr));
		if(chw::host2addr_ipv4(cond.exp_back.c_str(), cond.ipv4) == 1)
		{
			return chw::success;
		}
		else
		{
			return chw::fail;
		}
	}

	return chw::success;
}

/**
 * @brief ipv6地址转换为128位网络字节序
 * 
 * @param cond [in][out]条件表达式
 * @return uint32_t 转换成功或exp_back长度为0返回chw::success，否则返回chw::fail
 */
uint32_t FilterCondition::exp_back2ipv6(chw::FilterCond& cond)
{
	if(cond.exp_back.size() > 0)
	{
		_RAM_SET_(&cond.ipv6,sizeof(struct in6_addr),0,sizeof(struct in6_addr));
		if(chw::host2addr_ipv6(cond.exp_back.c_str(), cond.ipv6) == 1)
		{
			return chw::success;
		}
		else
		{
			return chw::fail;
		}
	}

	return chw::success;
}

/**
 * @brief mac地址转换为6字节数组
 * 
 * @param cond [in][out]条件表达式
 * @return uint32_t 转换成功或exp_back长度为0返回chw::success，否则返回chw::fail
 */
uint32_t FilterCondition::exp_back2mac(chw::FilterCond& cond)
{
	if(cond.exp_back.size() > 0)
	{
		_RAM_SET_(cond.mac,sizeof(cond.mac),0,sizeof(cond.mac));
		return chw::StrtoMacBuf(cond.exp_back.c_str(),cond.mac);
	}

	return chw::success;
}

/**
 * @brief 16进制以太类型转换位10进制
 * 
 * @param cond [in][out]条件表达式
 * @return uint32_t 转换成功或exp_back长度为0返回chw::success，否则返回chw::fail
 */
uint32_t FilterCondition::exp_back2ethtype(chw::FilterCond& cond)
{
	if(cond.exp_back.size() > 0)
	{
		std::string type = chw::StrHex2StrBuf(cond.exp_back.c_str());
		if(type.size() == 0)
		{
			return chw::fail;
		}
		else
		{
			cond.int_comm = *(uint16_t*)type.c_str();
		}
	}

	return chw::success;
}

/**
 * @brief 解析比较运算符前面的表达式 exp_front,获取 potol 和 option_val
 * 
 * @param cond [in][out]条件表达式
 * @return uint32_t 成功返回chw::success,失败返回chw::fail
 */
uint32_t FilterCondition::ParseFrontExp(chw::FilterCond& cond)
{
    if(cond.exp_front.size() < 2)
    {
        PrintD("Invalid para=%s",cond.exp_front.c_str());
        return chw::fail;
    }

    if(chw::start_with(cond.exp_front,"!") == true)
    {
        cond.non = true;
        cond.exp_front.erase(cond.exp_front.begin());
    }

    std::vector<std::string> vFornt = chw::split(cond.exp_front,".");
    if(vFornt[0] == "frame")
    {
        cond.potol = chw::_frame;
    }
    else if(vFornt[0] == "eth")
    {
        cond.potol = chw::_eth;
    }
    else if(vFornt[0] == "ip")
    {
        cond.potol = chw::_ip;
    }
	else if(vFornt[0] == "ipv6")
    {
        cond.potol = chw::_ipv6;
    }
    else if(vFornt[0] == "arp")
    {
        cond.potol = chw::_arp;
    }
    else if(vFornt[0] == "tcp")
    {
        cond.potol = chw::_tcp;
    }
    else if(vFornt[0] == "udp")
    {
        cond.potol = chw::_udp;
    }
    else
    {
        PrintD("Invalid exp_front=%s",cond.exp_front.c_str());
        return chw::fail;
    }

    if(vFornt.size() > 1)
    {
		switch(cond.potol)
		{
		case chw::_frame :
			if(vFornt[1] == "len")
			{
				cond.option_val = chw::frame_len;
			}
			else if(vFornt[1] == "cap_len")
			{
				cond.option_val = chw::frame_cap_len;
			}
			else if(vFornt[1] == "number")
			{
				cond.option_val = chw::frame_number;
			}
			else
			{
        		PrintD("Invalid option_val=%s,exp_front=%s", vFornt[1].c_str(),cond.exp_front.c_str());
				return chw::fail;
			}
			return exp_back2int(cond);
		case chw::_eth :
			if(vFornt[1] == "dst")
			{
				cond.option_val = chw::eth_dst;
				return exp_back2mac(cond);
			}
			else if(vFornt[1] == "src")
			{
				cond.option_val = chw::eth_src;
				return exp_back2mac(cond);
			}
			else if(vFornt[1] == "type")
			{
				cond.option_val = chw::eth_type;
				return exp_back2ethtype(cond);
			}
			else
			{
        		PrintD("Invalid option_val=%s,exp_front=%s", vFornt[1].c_str(),cond.exp_front.c_str());
				return chw::fail;
			}
			break;
		case chw::_ip:
			if(vFornt[1] == "hdr_len")
			{
				cond.option_val = chw::ip_hdr_len;
				return exp_back2int(cond);
			}
			else if(vFornt[1] == "version")
			{
				cond.option_val = chw::ip_version;
				return exp_back2int(cond);
			}
			else if(vFornt[1] == "tos")
			{
				cond.option_val = chw::ip_tos;
				return exp_back2int(cond);
			}
			else if(vFornt[1] == "len")
			{
				cond.option_val = chw::ip_len;
				return exp_back2int(cond);
			}
			else if(vFornt[1] == "id")
			{
				cond.option_val = chw::ip_id;
				return exp_back2ethtype(cond);
			}
			else if(vFornt[1] == "fragment")
			{
				cond.option_val = chw::ip_fragment;
				return exp_back2int(cond);
			}
			else if(vFornt[1] == "ttl")
			{
				cond.option_val = chw::ip_ttl;
				return exp_back2int(cond);
			}
			else if(vFornt[1] == "proto")
			{
				cond.option_val = chw::ip_proto;
				return exp_back2int(cond);
			}
			else if(vFornt[1] == "checksum")
			{
				cond.option_val = chw::ip_checksum;
//				return exp_back2int(cond);
				return exp_back2ethtype(cond);
			}
			else if(vFornt[1] == "src_host")
			{
				cond.option_val = chw::ip_src_host;
				return exp_back2ipv4(cond);
			}
			else if(vFornt[1] == "dst_host")
			{
				cond.option_val = chw::ip_dst_host;
				return exp_back2ipv4(cond);
			}
			else
			{
        		PrintD("Invalid option_val=%s,exp_front=%s", vFornt[1].c_str(),cond.exp_front.c_str());
				return chw::fail;
			}
			break;
		case chw::_ipv6:
			if(vFornt[1] == "version")
			{
				cond.option_val = chw::ipv6_version;
				return exp_back2int(cond);
			}
			else if(vFornt[1] == "flow")
			{
				cond.option_val = chw::ipv6_flow;
				return exp_back2int(cond);
			}
			else if(vFornt[1] == "plen")
			{
				cond.option_val = chw::ipv6_plen;
				return exp_back2int(cond);
			}
			else if(vFornt[1] == "nxt")
			{
				cond.option_val = chw::ipv6_nxt;
				return exp_back2int(cond);
			}
			else if(vFornt[1] == "src_host")
			{
				cond.option_val = chw::ipv6_src_host;
				return exp_back2ipv6(cond);
			}
			else if(vFornt[1] == "dst_host")
			{
				cond.option_val = chw::ipv6_dst_host;
				return exp_back2ipv6(cond);
			}
			else
			{
        		PrintD("Invalid option_val=%s,exp_front=%s", vFornt[1].c_str(),cond.exp_front.c_str());
				return chw::fail;
			}
			break;
		case chw::_tcp:
			if(vFornt[1] == "hdr_len")
			{
				cond.option_val = chw::tcp_hdr_len;
			}
			else if(vFornt[1] == "srcport")
			{
				cond.option_val = chw::tcp_srcport;
			}
			else if(vFornt[1] == "dstport")
			{
				cond.option_val = chw::tcp_dstport;
			}
			else if(vFornt[1] == "seq")
			{
				cond.option_val = chw::tcp_seq;
			}
			else if(vFornt[1] == "ack")
			{
				cond.option_val = chw::tcp_ack;
			}
			else if(vFornt[1] == "fin")
			{
				cond.option_val = chw::tcp_fin;
			}
			else if(vFornt[1] == "syn")
			{
				cond.option_val = chw::tcp_syn;
			}
			else if(vFornt[1] == "reset")
			{
				cond.option_val = chw::tcp_reset;
			}
			else if(vFornt[1] == "push")
			{
				cond.option_val = chw::tcp_push;
			}
			else if(vFornt[1] == "ack_flag")
			{
				cond.option_val = chw::tcp_ack_flag;
			}
			else if(vFornt[1] == "urg")
			{
				cond.option_val = chw::tcp_urg;
			}
			else if(vFornt[1] == "ece")
			{
				cond.option_val = chw::tcp_ece;
			}
			else if(vFornt[1] == "cwr")
			{
				cond.option_val = chw::tcp_cwr;
			}
			else if(vFornt[1] == "windows_size")
			{
				cond.option_val = chw::tcp_window_size;
			}
			else if(vFornt[1] == "checksum")
			{
				cond.option_val = chw::tcp_checksum;
				return exp_back2ethtype(cond);
			}
			else if(vFornt[1] == "urgent_pointer")
			{
				cond.option_val = chw::tcp_urgent_pointer;
			}
			else
			{
        		PrintD("Invalid option_val=%s,exp_front=%s", vFornt[1].c_str(),cond.exp_front.c_str());
				return chw::fail;
			}
			return exp_back2int(cond);
			break;
		case chw::_udp:
			if(vFornt[1] == "srcport")
			{
				cond.option_val = chw::udp_srcport;
			}
			else if(vFornt[1] == "dstport")
			{
				cond.option_val = chw::udp_dstport;
			}
			else if(vFornt[1] == "length")
			{
				cond.option_val = chw::udp_length;
			}
			else if(vFornt[1] == "checksum")
			{
				cond.option_val = chw::udp_checksum;
				return exp_back2ethtype(cond);
			}
			else
			{
        		PrintD("Invalid option_val=%s,exp_front=%s", vFornt[1].c_str(),cond.exp_front.c_str());
				return chw::fail;
			}
			return exp_back2int(cond);
			break;

		default:
        		PrintD("Invalid protol=%d,exp_front=%s", cond.potol,cond.exp_front.c_str());
				return chw::fail;
		}
    }

	return chw::success;
}
