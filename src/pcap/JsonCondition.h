// Copyright (c) 2024 The idump project authors. SPDX-License-Identifier: MIT.
// This file is part of idump(https://github.com/wichue/idump).

#ifndef __JSON_CONDITION_H
#define __JSON_CONDITION_H

#include "util.h"

namespace chw {
class JsonCondition {
public:
    JsonCondition() = default;
    ~JsonCondition() = default;

	/**
	 * @brief 解析json文件获取匹配条件
	 * 
	 * @param jsonpath	[in]json文件路径
	 */
    void ParseJson(const char* jsonpath);

	/**
	 * @brief 分隔通配符，获取每一个匹配字段
	 *
	 * @param compare	[in]json文件读取的compare
	 * @param condj		[out]json条件结构体
     * @return uint32_t 成功返回chw::success,失败返回chw::fail
	 */
	uint32_t split_wildcard(const std::string& compare, CondJson& condj);
};

}// namespace chw
#endif //__JSON_CONDITION_H
