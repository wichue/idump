// Copyright (c) 2024 The idump project authors. SPDX-License-Identifier: MIT.
// This file is part of idump(https://github.com/wichue/idump).

#include "Diameter.h"
#include "Logger.h"

namespace chw {

unordered_map<diameterhdr,dia_times> Diameter::_dia_time;
uint32_t _counts = 0;
uint32_t _times = 0;

uint32_t _max_delay = 0;
uint32_t _min_delay = 0;

// 计算时间差，单位毫秒
long time_diff_ms(const struct time_val *start, const struct time_val *end) {
    if (start == NULL || end == NULL) {
        return -1;
    }
    
    // 计算秒差和微秒差
    long sec_diff = end->tv_sec - start->tv_sec;
    long usec_diff = end->tv_usec - start->tv_usec;
    
    // 转换为毫秒
    long ms_diff = sec_diff * 1000 + usec_diff / 1000;
    
    return ms_diff;
}

/**
 * @brief 解析diameter相同Hop和End的数据包之间的时间间隔
 * 
 * @param data diameter协议数据
 * @param ayz 
 * @return uint32_t chw::success
 */
uint32_t Diameter::ParseChunkData(const char* data,const chw::ayz_info& ayz)
{
    diameterhdr* dia = (diameterhdr*)data;

    auto iter = _dia_time.find(*dia);
    if(iter != _dia_time.end()) {
        if(is_diameter_req((*iter).first.flags)) {
            (*iter).second.req_cnt ++;
        } else {
            (*iter).second.rsp_cnt ++;
        }
        
        char ip_str_src[INET_ADDRSTRLEN];  // 16字节足够存储"xxx.xxx.xxx.xxx"
        inet_ntop(AF_INET, &ayz.ip4->saddr, ip_str_src, INET_ADDRSTRLEN);

        char ip_str_dst[INET_ADDRSTRLEN];  // 16字节足够存储"xxx.xxx.xxx.xxx"
        inet_ntop(AF_INET, &ayz.ip4->daddr, ip_str_dst, INET_ADDRSTRLEN);

        long diff = time_diff_ms(&(*iter).second.time,&ayz.pcap->ts);
        PrintD("[%s##%s][%d]->[%d]time diff:%ld",ip_str_src,ip_str_dst,(*iter).second.uIndex_fst,ayz.uIndex,diff);

        if(diff > _max_delay) {
            _max_delay = diff;
        }

        if(_min_delay == 0) {
            _min_delay = diff;
        }
        if(diff < _min_delay) {
            _min_delay = diff;
        }
        _counts++;
        _times += diff;
    } else {
        // sctpchunkhdr* chunkhdr = (sctpchunkhdr*)((char*)ayz.sctp + sizeof(sctphdr));
        if(is_diameter_req(dia->flags)) {
            _dia_time[*dia] = dia_times(ayz.pcap->ts,ayz.uIndex,1,0);
        } else {
            _dia_time[*dia] = dia_times(ayz.pcap->ts,ayz.uIndex,0,1);
        }
    }

    return chw::success;
}
    
uint32_t Diameter::StatDiameter()
{
    if(_counts == 0)
    {
        PrintD("error: No diameter package.");
        return chw::success;
    }
    PrintD("avg time:%u,max:%u,min:%u.",_times/_counts,_max_delay,_min_delay);

    auto iter = _dia_time.begin();
    while(iter != _dia_time.end()) {
        if((*iter).second.req_cnt > 1) {
            PrintD("[%d]req_cnt:%u",(*iter).second.uIndex_fst,(*iter).second.req_cnt);
        }

        if((*iter).second.rsp_cnt > 1) {
            PrintD("[%d]rsp_cnt:%u",(*iter).second.uIndex_fst,(*iter).second.rsp_cnt);
        }
        iter++;
    }

    return chw::success;
}

} //namespace chw