// Copyright (c) 2024 The idump project authors. SPDX-License-Identifier: MIT.
// This file is part of idump(https://github.com/wichue/idump).

#ifndef UTIL_UTIL_H_
#define UTIL_UTIL_H_

#include <memory>// for std::shared_ptr
#include <vector>
#include <time.h>
#if defined(_WIN32)
#undef FD_SETSIZE
//修改默认64为1024路  [AUTO-TRANSLATED:90567e14]
//Modify the default 64 to 1024 paths
#define FD_SETSIZE 1024
#include <winsock2.h>
#pragma comment (lib,"WS2_32")
#else
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <cstddef>
#endif // defined(_WIN32)
#include <sstream>
#include "ComProtocol.h"

// 单例宏
#define INSTANCE_IMP(class_name, ...) \
class_name &class_name::Instance() { \
    static std::shared_ptr<class_name> s_instance(new class_name(__VA_ARGS__)); \
    static class_name &s_instance_ref = *s_instance; \
    return s_instance_ref; \
}

namespace chw {

/**
 * @brief Set the Thread Name object
 * 
 * @param name 
 */
void setThreadName(const char *name);

/**
 * @brief TimeSecond
 * @return 从1970年到现在过去的秒数
 */
time_t TimeSecond();

/**
 * @brief TimeSecond
 * @return 从1970年到现在过去的秒数,精确到6位小数点，微秒
 */
double TimeSecond_dob();

/**
 * @brief Get the Thread Name object
 * 
 * @return std::string 
 */
std::string getThreadName();

/**
 * 根据unix时间戳获取本地时间
 * @param [in]sec unix时间戳
 * @return tm结构体
 */
struct tm getLocalTime(time_t sec);

/**
 * 获取时间字符串
 * @param fmt [in]时间格式，譬如%Y-%m-%d %H:%M:%S
 * @return 时间字符串
 */
std::string getTimeStr(const char *fmt,time_t time = 0);

//判断是否为ipv4
bool is_ipv4(const char *host);
//判断是否为ipv6
bool is_ipv6(const char *host);
//判断是否为ip
bool isIP(const char *str);

/**
 * @brief ipv4地址转换为字符串
 * 
 * @param addr  [in]ip地址
 * @return std::string .分ip地址字符串
 */
std::string sockaddr_ipv4(uint32_t addr);

/**
 * @brief ipv6地址转换为字符串
 * 
 * @param addr  [in]ip地址
 * @return std::string :分ip地址字符串
 */
std::string sockaddr_ipv6(uint8_t* addr);

/**
 * @brief 点分ipv4地址转换为32位网络字节序
 * 
 * @param host  [in]点分ip地址
 * @param addr  [out]32位ip地址
 * @return int32_t 若成功则为1，若输入不是有效的表达式则为0，若出错则为-1
 */
int32_t host2addr_ipv4(const char* host, struct in_addr& addr);

/**
 * @brief :分ipv6地址转换为128位网络字节序
 * 
 * @param host  [in]:分ip地址
 * @param addr  [out]32位ip地址
 * @return int32_t 若成功则为1，若输入不是有效的表达式则为0，若出错则为-1
 */
int32_t host2addr_ipv6(const char* host, struct in6_addr& addr6);

/**
 * @brief 内存mac地址转换为字符串
 * 
 * @param macAddress    [in]mac地址buf
 * @return std::string  :分mac地址字符串
 */
std::string MacBuftoStr(const unsigned char* mac_buf);

/**
 * @brief :分mac地址字符串转换为6字节buf
 * 
 * @param charArray     [in]:分mac地址字符串
 * @param macAddress    [out]6字节长度buf
 * @return uint32_t 成功返回chw::success,失败返回chw::fail
 */
uint32_t StrtoMacBuf(const char* charArray, unsigned char* macAddress);

bool isValidMacAddress(const std::string& mac);

#if defined(__linux__) || defined(__linux)
/**
 * @brief 判断字符串是否有效的mac地址
 * 
 * @param mac   [in]字符串
 * @return uint32_t 成功返回chw::success,失败返回chw::fail
 */
uint32_t is_valid_mac_addr(const char* mac);
#endif// defined(__linux__) || defined(__linux)

//字符串是否以xx开头
bool start_with(const std::string &str, const std::string &substr);
//字符串是否以xx结尾
bool end_with(const std::string &str, const std::string &substr);
//返回可执行文件路径，包含可执行文件名
std::string exePath(bool isExe = true);
//返回可执行文件路径，不包含可执行文件名
std::string exeDir(bool isExe = true);
//返回可执行文件名
std::string exeName(bool isExe = true);
// 返回文件后缀名
const char* suffixname(const char* filename);

// string转小写
std::string& strToLower(std::string& str);
std::string strToLower(std::string&& str);
// string转大写
std::string& strToUpper(std::string& str);
std::string strToUpper(std::string&& str);

/**
 * @brief 统计字符串中包含某字符的数量
 * 
 * @param msg		[in]字符串
 * @param c			[in]字符
 * @return 字符数量
 */
uint32_t count_char(const std::string& msg, char c);

/**
 * @brief 字符串分割
 * 
 * @param s        [in]输入字符串
 * @param delim    [in]分隔符
 * @return std::vector<std::string> 分割得到的子字符串集
 */
std::vector<std::string> split(const std::string& s, const char *delim);

/**
 * @brief 字符串分割
 * 
 * @param s        [in]输入字符串
 * @param delim    [in]分隔符
 * @return std::vector<spit_string> 分割得到的子字符串集结构体
 */
std::vector<spit_string> split_pos(const std::string &s, const char *delim);

/**
 * @brief 以16进制打印内存，两个字符表示一个字节，每一行固定字节数量，字节之间有空格
 * 
 * @param pBuff [in]内存
 * @param nLen  [in]内存长度
 */
void PrintBuffer(void* pBuff, unsigned int nLen, chw::ayz_info& ayz);

/**
 * @brief 判断字符串是否为空
 * @param value [in]入参字符串
 * @return true字符串为空，false字符串不为空
 */
bool StrIsNull(const char *value);

/**
 * @brief 将16进制字符转换为10进制
 * @param hex   [in]16进制字符
 * @return      转换后的10进制
 */
unsigned char HextoInt(unsigned char hex);

/**
 * @brief 16进制表示字符串转换成16进制内存buf ("0080"字符串 -> 查看内存是0080)
 * @param value [in]要转换的字符串
 * @return      返回转换的结果
 */
std::string StrHex2StrBuf(const char *value);
//遇到wild_card时通配符不进行进制转换，wild_card和其后的一个字符被转换为1个wild_card字符
std::string StrHex2StrBuf(const char *value,char wild_card);

/**
 * @brief 将内存buffer转换成16进制形式字符串(内存16进制0800->"0800"字符串)
 * @param value [in]buffer
 * @param len   [in]长度
 * @return      转换后的字符串
 */
std::string HexBuftoString(const unsigned char *value, int len);

/**
 * @brief 替换字符串中的子串
 * 
 * @param str   [in]字符串
 * @param find  [in]子串
 * @param rep   [in]替换为的串
 * @return std::string 替换后的字符串
 */
std::string replaceAll(const std::string& str, const std::string& find, const std::string& rep);

// 模板函数：将string类型变量转换为常用的数值类型（此方法具有普遍适用性）
// 遇到非数字字符停止，停止前没有数字字符则返回0
template <class Type>
Type String2Num(const std::string& str){
	std::istringstream iss(str);
	Type num;
	iss >> num;
	return num;
}


/**
 * @brief 取4字节整数的低4位，高28位补0，示例:100(...0110 0100)——>4(...0000 0100)
 * 
 * @param num	[in]输入整数
 * @return 	    转换后的整数
 */
int32_t int32_lowfour(int32_t num);

/**
 * @brief 取4字节整数的高4位，低28位补0
 * 
 * @param num	[in]输入整数
 * @return 	    转换后的整数
 */
int32_t int32_highfour(int32_t num);

/**
 * @brief 取2字节整数的低4位，高12位补0
 * 
 * @param num	[in]输入整数
 * @return 	    转换后的整数
 */
int16_t int16_lowfour(int16_t num);

/**
 * @brief 取2字节整数的高4位，低12位补0
 * 
 * @param num	[in]输入整数
 * @return 	    转换后的整数
 */
int16_t int16_highfour(int16_t num);

/**
 * @brief 取1字节整数的低4位，高4位补0
 * 
 * @param num	[in]输入整数
 * @return 	    转换后的整数
 */
int8_t int8_lowfour(int8_t num);

/**
 * @brief 取1字节整数的高4位，低4位补0
 * 
 * @param num	[in]输入整数
 * @return 	    转换后的整数
 */
int8_t int8_highfour(int8_t num);

#if defined(_WIN32)
int gettimeofday(struct timeval* tp, void* tzp);
void usleep(int micro_seconds);
void sleep(int second);
int vasprintf(char** strp, const char* fmt, va_list ap);
int asprintf(char** strp, const char* fmt, ...);
const char* strcasestr(const char* big, const char* little);

#if !defined(strcasecmp)
#define strcasecmp _stricmp
#endif

#if !defined(strncasecmp)
#define strncasecmp _strnicmp
#endif

#ifndef ssize_t
#ifdef _WIN64
#define ssize_t int64_t
#else
#define ssize_t int32_t
#endif
#endif
#endif //WIN32

//禁止拷贝基类
class noncopyable {
protected:
    noncopyable() {}
    ~noncopyable() {}
private:
    //禁止拷贝
    noncopyable(const noncopyable &that) = delete;
    noncopyable(noncopyable &&that) = delete;
    noncopyable &operator=(const noncopyable &that) = delete;
    noncopyable &operator=(noncopyable &&that) = delete;
};

} /* namespace chw */
#endif // UTIL_UTIL_H_
