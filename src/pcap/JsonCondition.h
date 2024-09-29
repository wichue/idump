// Copyright (c) 2024 The idump project authors. SPDX-License-Identifier: MIT.
// This file is part of idump(https://github.com/wichue/idump).

#ifndef __JSON_CONDITION_H
#define __JSON_CONDITION_H

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
};

}// namespace chw
#endif //__JSON_CONDITION_H
