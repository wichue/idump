#include "JsonCondition.h"

#include "File.h"
#include "picojson.h"
#include "Logger.h"
#include "GlobalValue.h"
#include "util.h"

void JsonCondition::ParseJson(char* jsonpath)
{
    std::string json = chw::File::loadFile(jsonpath);

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
                tCondJson.start = atoi(obj_i.at("start").get<std::string>().c_str());
                std::string cmp = obj_i.at("compare").get<std::string>();
                tCondJson.compare = chw::StrHex2StrBuf(cmp.c_str(),'*');
                tCondJson.desc = obj_i.at("desc").get<std::string>();

                PrintD("cond index=%d,start=%u,compare=%s,desc=%s",index, tCondJson.start, cmp.c_str(), tCondJson.desc.c_str());
                index++;
                g_vCondJson.push_back(tCondJson);
            }
        }
    }
}