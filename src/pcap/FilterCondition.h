#ifndef __FILTER_CONDITION_H
#define __FILTER_CONDITION_H

class FilterCondition {
public:
    FilterCondition() = default;
    ~FilterCondition() = default;

    void ParseJson(char* jsonpath);
};


#endif //__FILTER_CONDITION_H
