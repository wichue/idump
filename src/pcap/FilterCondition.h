// Copyright (c) 2024 The idump project authors. SPDX-License-Identifier: MIT.
// This file is part of idump(https://github.com/wichue/idump).

#ifndef __FILTER_CONDITION_H
#define __FILTER_CONDITION_H

#include "ComProtocol.h"

namespace chw {

class FilterCondition {
public:
    FilterCondition() = default;
    ~FilterCondition() = default;

	/**
	 * @brief 解析命令行--filter过滤条件
	 * 
	 * @param filter 	过滤条件字符串
	 */
    void ParseFilter(char* filter);
private:
    /**
     * @brief 解析比较运算符前面的表达式,获取 potol 和 option_val
     * 
     * @param cond [in][out]条件表达式
     * @return uint32_t 成功返回chw::success,失败返回chw::fail
     */
    uint32_t ParseFrontExp(chw::FilterCond& cond);

	/**
	 * @brief 后置表达式转换为整数
	 * 
	 * @param cond [in][out]条件表达式
	 * @return uint32_t 转换成功或exp_back长度为0返回chw::success，否则返回chw::fail
	 */
    uint32_t exp_back2int(chw::FilterCond& cond);

	/**
	 * @brief 后置表达式ipv4地址转换为32位网络字节序
	 * 
	 * @param cond [in][out]条件表达式
	 * @return uint32_t 转换成功或exp_back长度为0返回chw::success，否则返回chw::fail
	 */
    uint32_t exp_back2ipv4(chw::FilterCond& cond);

	/**
	 * @brief 后置表达式转换为128位ipv6地址
	 * 
	 * @param cond [in][out]条件表达式
	 * @return uint32_t 转换成功或exp_back长度为0返回chw::success，否则返回chw::fail
	 */
    uint32_t exp_back2ipv6(chw::FilterCond& cond);

	/**
	 * @brief 后置表达式mac地址转换为6字节数组
	 * 
	 * @param cond [in][out]条件表达式
	 * @return uint32_t 转换成功或exp_back长度为0返回chw::success，否则返回chw::fail
	 */
    uint32_t exp_back2mac(chw::FilterCond& cond);
	/**
	* @brief 16进制以太类型转换为10进制
 	* 
	* @param cond [in][out]条件表达式
	* @return uint32_t 转换成功或exp_back长度为0返回chw::success，否则返回chw::fail
	*/
    uint32_t exp_back2ethtype(chw::FilterCond& cond);
};


}// namespace chw
#endif //__FILTER_CONDITION_H
