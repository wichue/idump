#ifndef __FILTER_CONDITION_H
#define __FILTER_CONDITION_H

#include "ComProtocol.h"

class FilterCondition {
public:
    FilterCondition() = default;
    ~FilterCondition() = default;

    void ParseFilter(char* filter);
private:
    /**
     * @brief 解析比较运算符前面的表达式,获取 potol 和 option_val
     * 
     * @param cond [in][out]条件表达式
     * @return uint32_t 成功返回chw::success,失败返回chw::fail
     */
    uint32_t ParseFrontExp(chw::FilterCond& cond);

    uint32_t exp_back2int(chw::FilterCond& cond);
    uint32_t exp_back2ipv4(chw::FilterCond& cond);
    uint32_t exp_back2ipv6(chw::FilterCond& cond);
    uint32_t exp_back2mac(chw::FilterCond& cond);
};



#endif //__FILTER_CONDITION_H