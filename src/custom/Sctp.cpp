// Copyright (c) 2024 The idump project authors. SPDX-License-Identifier: MIT.
// This file is part of idump(https://github.com/wichue/idump).

#include "Sctp.h"
#include "Logger.h"
#include "Diameter.h"

namespace chw {

/**
 * @brief 获取sctp协议的数据块DATA和SACK
 * 
 * @return uint32_t  成功返回chw::success,失败返回chw::fail
 */
uint32_t Sctp::ParseSctp(const chw::ayz_info& ayz)
{
    uint32_t offset = sizeof(sctphdr);
    while(offset < ayz.trans_load_len) {

        sctpchunkhdr* chunkhdr = (sctpchunkhdr*)((char*)ayz.sctp + offset);

        if(chunkhdr->type == 0x00) {//DATA
            Diameter::ParseChunkData((const char*)chunkhdr + sizeof(sctpchunkData),ayz);
        } else if(chunkhdr->type == 0x03) {//SACK

        }

        if(chunkhdr->length <= 0) {
            return chw::fail;
        }

        offset += ntohs(chunkhdr->length);
        continue;
    }

    return chw::success;
}

}// namespace chw