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
     * @brief 解析比较运算符前面的表达式
     * 
     * @param cond 
     */
    void ParseFrontExp(chw::FilterCond& cond);
};



#endif //__FILTER_CONDITION_H