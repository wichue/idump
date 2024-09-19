#ifndef __GLOBAL_VALUE_H
#define __GLOBAL_VALUE_H
#include "ComProtocol.h"
#include <vector>

extern chw::ConfigCmd gConfigCmd;//命令行参数
extern std::vector<chw::CondJson> g_vCondJson;// 读取自json的匹配条件
extern std::vector<chw::FilterCond> g_vCondFilter;// 读取自命令行的过滤条件

#endif //__GLOBAL_VALUE_H
