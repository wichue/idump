#include "FilterCondition.h"
#include <string>
#include <vector>
#include "util.h"
#include "Logger.h"
#include "GlobalValue.h"

void FilterCondition::ParseFilter(char* filter)
{
    std::string filter_trim = chw::replaceAll(filter," ","");
    PrintD("filter_trim=%s\n",filter_trim.c_str());

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


        if(list.size() == 2)
        {
            //3.解析单个条件表达式
            ParseFrontExp(*iter_cond);
            iter_cond++;
        }
        else
        {
            PrintD("unknown operator,desc=%s",iter_cond->desc.c_str());
            iter_cond = g_vCondFilter.erase(iter_cond);
        }
    }

}

/**
 * @brief 解析比较运算符前面的表达式
 * 
 * @param cond 
 */
void FilterCondition::ParseFrontExp(chw::FilterCond& cond)
{
    if(cond.exp_front.size() < 2)
    {
        PrintD("Invalid para=%s",cond.exp_front.c_str());
        return;
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
        return;
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
			else
			{
        		PrintD("Invalid option_val=%s,exp_front=%s", vFornt[1].c_str(),cond.exp_front.c_str());
				return;
			}
			break;
		case chw::_eth :
			if(vFornt[1] == "dst")
			{
				cond.option_val = chw::eth_dst;
			}
			else if(vFornt[1] == "src")
			{
				cond.option_val = chw::eth_src;
			}
			else if(vFornt[1] == "type")
			{
				cond.option_val = chw::eth_type;
			}
			else
			{
        		PrintD("Invalid option_val=%s,exp_front=%s", vFornt[1].c_str(),cond.exp_front.c_str());
				return;
			}
			break;
		case chw::_ip:
			if(vFornt[1] == "hdr_len")
			{
				cond.option_val = chw::ip_hdr_len;
			}
			else if(vFornt[1] == "version")
			{
				cond.option_val = chw::ip_version;
			}
			else if(vFornt[1] == "tos")
			{
				cond.option_val = chw::ip_tos;
			}
			else if(vFornt[1] == "len")
			{
				cond.option_val = chw::ip_len;
			}
			else if(vFornt[1] == "id")
			{
				cond.option_val = chw::ip_id;
			}
			else if(vFornt[1] == "fragment")
			{
				cond.option_val = chw::ip_fragment;
			}
			else if(vFornt[1] == "ttl")
			{
				cond.option_val = chw::ip_ttl;
			}
			else if(vFornt[1] == "proto")
			{
				cond.option_val = chw::ip_proto;
			}
			else if(vFornt[1] == "checksum")
			{
				cond.option_val = chw::ip_checksum;
			}
			else if(vFornt[1] == "saddr")
			{
				cond.option_val = chw::ip_saddr;
			}
			else if(vFornt[1] == "daddr")
			{
				cond.option_val = chw::ip_daddr;
			}
			else
			{
        		PrintD("Invalid option_val=%s,exp_front=%s", vFornt[1].c_str(),cond.exp_front.c_str());
				return;
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
			}
			else if(vFornt[1] == "urgent_pointer")
			{
				cond.option_val = chw::tcp_urgent_pointer;
			}
			else
			{
        		PrintD("Invalid option_val=%s,exp_front=%s", vFornt[1].c_str(),cond.exp_front.c_str());
				return;
			}
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
			}
			else
			{
        		PrintD("Invalid option_val=%s,exp_front=%s", vFornt[1].c_str(),cond.exp_front.c_str());
				return;
			}
			break;

		default:
        		PrintD("Invalid protol=%d,exp_front=%s", cond.potol,cond.exp_front.c_str());
			break;
		}
    }
}
