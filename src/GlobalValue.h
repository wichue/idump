// Copyright (c) 2024 The idump project authors. SPDX-License-Identifier: MIT.
// This file is part of idump(https://github.com/wichue/idump).

#ifndef __GLOBAL_VALUE_H
#define __GLOBAL_VALUE_H
#include "ComProtocol.h"
#include <vector>

namespace chw {

extern chw::ConfigCmd gConfigCmd;//命令行参数
extern std::vector<chw::CondJson> g_vCondJson;// 读取自json的匹配条件
extern std::vector<chw::FilterCond> g_vCondFilter;// 读取自命令行的过滤条件

}// namespace chw
#endif //__GLOBAL_VALUE_H
