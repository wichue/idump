#include "FilterCondition.h"
#include <string>
#include <vector>
#include "util.h"
#include "Logger.h"

void FilterCondition::ParseFilter(char* filter)
{
    std::string filter_trim = chw::replaceAll(filter," ","");
    PrintD("filter_trim=%s\n",filter_trim.c_str());

    std::vector<chw::FilterCond> conds;
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
            conds.push_back(tcond);
            index++;
            iter_and++;
        }
        iter_or++;
    }

    //2.解析比较运算符
    auto iter_cond = conds.begin();
    while(iter_cond != conds.end())
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
            PrintD("unknown operator,desc=%s.\n",iter_cond->desc.c_str());
            iter_cond = conds.erase(iter_cond);
        }
    }

}

void FilterCondition::ParseFrontExp(chw::FilterCond& cond)
{
    if(cond.exp_front.size() < 2)
    {
        PrintD("Invalid para=%s\n",cond.exp_front.c_str());
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
        PrintD("Invalid para=%s\n",cond.exp_front.c_str());
        return;
    }

    if(vFornt.size() > 1)
    {
        cond.value = vFornt[1];
    }
}