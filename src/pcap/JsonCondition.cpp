// Copyright (c) 2024 The idump project authors. SPDX-License-Identifier: MIT.
// This file is part of idump(https://github.com/wichue/idump).

#include "JsonCondition.h"

#include "File.h"
#include "picojson.h"
#include "Logger.h"
#include "GlobalValue.h"
#include "util.h"

namespace chw {

/**
 * @brief 解析json文件获取匹配条件
 * 
 * @param jsonpath	[in]json文件路径
 */
void JsonCondition::ParseJson(const char* jsonpath)
{
    std::string json = chw::loadFile(jsonpath);

    //1.解析字符串，获取json value
    picojson::value val_root;
    std::string err = picojson::parse(val_root, json);
    if (! err.empty()) {
        PrintD("ParseJson err=%s",err.c_str());
    }

    if (val_root.is<picojson::object>())
    {
        //2.根据value获取object
        //object 是类似map的键值对，使用迭代器遍历，根据key取值，key和值可打印出来
        //例如<name,cond1>，<conds,[{"compare":"0800","desc":"ipv4","start":"13"},{"compare":"86dd","desc":"ipv6","start":"13"}]>
        const picojson::object &obj_one = val_root.get<picojson::object>();

        //3.从object获取字段的string
        std::string cond_name = obj_one.at("name").get<std::string>();
        PrintD("cond name=%s",cond_name.c_str());

        //4.从object获取一个value
        picojson::value val_array = obj_one.at("conds");
        if (val_array.is<picojson::array>()) 
        {
            //5.value 转换为 array
            const picojson::array &arr = val_array.get<picojson::array>();
            int index = 0;
            for (picojson::array::const_iterator i = arr.begin(); i != arr.end(); ++i) 
            {
                chw::CondJson tCondJson;
                //6.array 数组使用迭代遍历，每个元素转换为object解析
                const picojson::object &obj_i = (*i).get<picojson::object>();

                std::string cmp = obj_i.at("compare").get<std::string>();
                cmp = chw::replaceAll(cmp," ","");
				if(split_wildcard(cmp,tCondJson) == chw::fail)
				{
					index++;
					PrintD("Invalid json compare condition:%s, an * or char represents 2 bytes,erase it.", cmp.c_str());
					continue;
				}

                tCondJson.start = atoi(obj_i.at("start").get<std::string>().c_str());
                tCondJson.desc = obj_i.at("desc").get<std::string>();

                PrintD("cond index=%d,start=%u,compare=%s,desc=%s",index, tCondJson.start, cmp.c_str(), tCondJson.desc.c_str());
                index++;
                g_vCondJson.push_back(tCondJson);
            }
        }
    }
}

/**
 * @brief 分隔通配符，获取每一个匹配字段
 *
 * @param compare	[in]json文件读取的compare
 * @param condj		[out]json条件结构体
 * @return uint32_t 成功返回chw::success,失败返回chw::fail
 */
uint32_t JsonCondition::split_wildcard(const std::string& compare, CondJson& condj)
{
	condj.totalLen = compare.size();
	if(condj.totalLen % 2 != 0)
	{
		PrintD("json compare number must integer times of 2.An * or char represents 2 bytes,compare:%s.", compare.c_str());
		return chw::fail;
	}
	condj.totalLen /= 2;

	condj.vsCompare = split_pos(compare,"*");
	auto iter = condj.vsCompare.begin();
	while(iter != condj.vsCompare.end())
	{
		std::string ret = chw::StrHex2StrBuf(iter->str.c_str());
		if(ret.size() == 0)
		{
			iter = condj.vsCompare.erase(iter);
			return chw::fail;
		}
		else
		{
			iter->str = ret;
			iter->uIndex /= 2;
			iter ++;
		}
	}

	return condj.vsCompare.size() == 0 ? chw::fail : chw::success;
}

}// namespace chw
