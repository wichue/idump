// Copyright (c) 2024 The idump project authors. SPDX-License-Identifier: MIT.
// This file is part of idump(https://github.com/wichue/idump).

#ifndef __DIAMETER_H
#define __DIAMETER_H

#include <stdint.h>
#include <unordered_map>
#include "ComProtocol.h"

namespace chw {

using namespace std;
class Diameter {
public:
    Diameter() = default;
    ~Diameter() = default;

public:
    static uint32_t StatDiameter();
    static uint32_t ParseChunkData(const char* data,const chw::ayz_info& ayz);
private:
    static unordered_map<diameterhdr,dia_times> _dia_time;
};

}// namespace chw

//自定义数据类型生成hash值的方式
namespace std
{
    template<>
    struct hash<chw::diameterhdr>: public __hash_base<size_t, chw::diameterhdr>
    {
        size_t operator()(const chw::diameterhdr& dia) const noexcept
        {
            //自定义哈希值的生成方式
            return (std::hash<int>()(dia.hop_by_hop_id)) ^ (std::hash<int>()(dia.end_to_end_id) << 1);
        }
    };
}

#endif //#define __DIAMETER_H