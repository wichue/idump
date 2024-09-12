#ifndef __JSON_CONDITION_H
#define __JSON_CONDITION_H

class JsonCondition {
public:
    JsonCondition() = default;
    ~JsonCondition() = default;

    void ParseJson(char* jsonpath);
};


#endif //__JSON_CONDITION_H
