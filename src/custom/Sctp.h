// Copyright (c) 2024 The idump project authors. SPDX-License-Identifier: MIT.
// This file is part of idump(https://github.com/wichue/idump).

#ifndef __SCTP_H
#define __SCTP_H

#include <stdint.h>
#include <unordered_map>
#include "ComProtocol.h"

namespace chw {

using namespace std;
class Sctp {
public:
    Sctp() = default;
    ~Sctp() = default;

public:
    static uint32_t ParseSctp(const chw::ayz_info& ayz);//获取sctp协议的数据块DATA和SACK
};

}// namespace chw



#endif //#define __SCTP_H