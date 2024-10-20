// Copyright (c) 2024 The idump project authors. SPDX-License-Identifier: MIT.
// This file is part of idump(https://github.com/wichue/idump).

#include "util.h"
#include <assert.h>
//#include <pthread.h>
#include <limits.h>//for PATH_MAX
//#include <unistd.h>
#include <string.h>
#include <string>
#include <time.h>
//#include <arpa/inet.h>
//#include <sys/ioctl.h>
//#include <sys/socket.h>
//#include <net/if.h>
//#include <netinet/in.h>
#include <stdio.h>
#include <sys/types.h>
#if defined(__linux__) || defined(__linux)
#include <regex.h>
#endif// defined(__linux__) || defined(__linux)
#include <algorithm>
#include <iostream>
#include <regex>
#include <string>

#include "local_time.h"
#include "Logger.h"
#include "MemoryHandle.h"
#include "GlobalValue.h"
#include "File.h"

#if defined(_WIN32)
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <shlwapi.h>
#pragma comment(lib, "shlwapi.lib")
extern "C" const IMAGE_DOS_HEADER __ImageBase;
#endif // defined(_WIN32)

using namespace std;
namespace chw {

static std::string limitString(const char *name, size_t max_size) {
    std::string str = name;
    if (str.size() + 1 > max_size) {
        auto erased = str.size() + 1 - max_size + 3;
        str.replace(5, erased, "...");
    }
    return str;
}

/**
 * @brief Set the Thread Name object
 * 
 * @param name 
 */
void setThreadName(const char *name) {
    assert(name);
#if defined(__linux) || defined(__linux__) || defined(__MINGW32__)
    pthread_setname_np(pthread_self(), limitString(name, 16).data());
#elif defined(__MACH__) || defined(__APPLE__)
    pthread_setname_np(limitString(name, 32).data());
#elif defined(_MSC_VER)
    // SetThreadDescription was added in 1607 (aka RS1). Since we can't guarantee the user is running 1607 or later, we need to ask for the function from the kernel.
    using SetThreadDescriptionFunc = HRESULT(WINAPI * )(_In_ HANDLE hThread, _In_ PCWSTR lpThreadDescription);
    static auto setThreadDescription = reinterpret_cast<SetThreadDescriptionFunc>(::GetProcAddress(::GetModuleHandle((LPCWSTR)"Kernel32.dll"), "SetThreadDescription"));
    if (setThreadDescription) {
        // Convert the thread name to Unicode
        wchar_t threadNameW[MAX_PATH];
        size_t numCharsConverted;
        errno_t wcharResult = mbstowcs_s(&numCharsConverted, threadNameW, name, MAX_PATH - 1);
        if (wcharResult == 0) {
            HRESULT hr = setThreadDescription(::GetCurrentThread(), threadNameW);
            if (!SUCCEEDED(hr)) {
                int i = 0;
                i++;
            }
        }
    } else {
        // For understanding the types and values used here, please see:
        // https://docs.microsoft.com/en-us/visualstudio/debugger/how-to-set-a-thread-name-in-native-code

        const DWORD MS_VC_EXCEPTION = 0x406D1388;
#pragma pack(push, 8)
        struct THREADNAME_INFO {
            DWORD dwType = 0x1000; // Must be 0x1000
            LPCSTR szName;         // Pointer to name (in user address space)
            DWORD dwThreadID;      // Thread ID (-1 for caller thread)
            DWORD dwFlags = 0;     // Reserved for future use; must be zero
        };
#pragma pack(pop)

        THREADNAME_INFO info;
        info.szName = name;
        info.dwThreadID = (DWORD) - 1;

        __try{
                RaiseException(MS_VC_EXCEPTION, 0, sizeof(info) / sizeof(ULONG_PTR), reinterpret_cast<const ULONG_PTR *>(&info));
        } __except(GetExceptionCode() == MS_VC_EXCEPTION ? EXCEPTION_CONTINUE_EXECUTION : EXCEPTION_EXECUTE_HANDLER) {
        }
    }
#else
    thread_name = name ? name : "";
#endif
}

/**
 * @brief Get the Thread Name object
 * 
 * @return std::string 
 */
std::string getThreadName() {
#if ((defined(__linux) || defined(__linux__)) && !defined(ANDROID)) || (defined(__MACH__) || defined(__APPLE__)) || (defined(ANDROID) && __ANDROID_API__ >= 26) || defined(__MINGW32__)
    std::string ret;
    ret.resize(32);
    auto tid = pthread_self();
    pthread_getname_np(tid, (char *) ret.data(), ret.size());
    if (ret[0]) {
        ret.resize(strlen(ret.data()));
        return ret;
    }
    return std::to_string((uint64_t) tid);
#elif defined(_MSC_VER)
    using GetThreadDescriptionFunc = HRESULT(WINAPI * )(_In_ HANDLE hThread, _In_ PWSTR * ppszThreadDescription);
    static auto getThreadDescription = reinterpret_cast<GetThreadDescriptionFunc>(::GetProcAddress(::GetModuleHandleA("Kernel32.dll"), "GetThreadDescription"));

    if (!getThreadDescription) {
        std::ostringstream ss;
        ss << std::this_thread::get_id();
        return ss.str();
    } else {
        PWSTR data;
        HRESULT hr = getThreadDescription(GetCurrentThread(), &data);
        if (SUCCEEDED(hr) && data[0] != '\0') {
            char threadName[MAX_PATH];
            size_t numCharsConverted;
            errno_t charResult = wcstombs_s(&numCharsConverted, threadName, data, MAX_PATH - 1);
            if (charResult == 0) {
                LocalFree(data);
                std::ostringstream ss;
                ss << threadName;
                return ss.str();
            } else {
                if (data) {
                    LocalFree(data);
                }
                return to_string((uint64_t) GetCurrentThreadId());
            }
        } else {
            if (data) {
                LocalFree(data);
            }
            return to_string((uint64_t) GetCurrentThreadId());
        }
    }
#else
    if (!thread_name.empty()) {
        return thread_name;
    }
    std::ostringstream ss;
    ss << std::this_thread::get_id();
    return ss.str();
#endif
}

/**
 * @brief TimeSecond
 * @return 从1970年到现在过去的秒数
 */
time_t TimeSecond() {
    time_t t;
    time(&t);
    return t;
}

/**
 * @brief TimeSecond
 * @return 从1970年到现在过去的秒数,精确到6位小数点，微秒
 */
double TimeSecond_dob() {
    struct timeval _time;
    gettimeofday(&_time, NULL);
    return (double)(_time.tv_sec * 1000*1000 + _time.tv_usec) /  (1000*1000);
}

/**
 * 根据unix时间戳获取本地时间
 * @param [in]sec unix时间戳
 * @return tm结构体
 */
struct tm getLocalTime(time_t sec) {
    struct tm tm;
#ifdef _WIN32
    localtime_s(&tm, &sec);
#else
    no_locks_localtime(&tm, sec);
#endif //_WIN32
    return tm;
}

/**
 * 获取时间字符串
 * @param fmt [in]时间格式，譬如%Y-%m-%d %H:%M:%S
 * @return 时间字符串
 */
std::string getTimeStr(const char *fmt, time_t time) {
    if (!time) {
        time = ::time(nullptr);
    }
    auto tm = getLocalTime(time);
    size_t size = strlen(fmt) + 64;
    std::string ret;
    ret.resize(size);
    size = strftime(&ret[0], size, fmt, &tm);
    if (size > 0) {
        ret.resize(size);
    }
    else{
        ret = fmt;
    }
    return ret;
}

bool start_with(const std::string &str, const std::string &substr) {
    return str.find(substr) == 0;
}

bool end_with(const std::string &str, const std::string &substr) {
    auto pos = str.rfind(substr);
    return pos != std::string::npos && pos == str.size() - substr.size();
}

bool is_ipv4(const char *host) {
    struct in_addr addr;
    return 1 == inet_pton(AF_INET, host, &addr);
}

bool is_ipv6(const char *host) {
    struct in6_addr addr;
    return 1 == inet_pton(AF_INET6, host, &addr);
}

bool isIP(const char *str) {
    return is_ipv4(str) || is_ipv6(str);
}

/**
 * @brief ipv4地址转换为字符串
 * 
 * @param addr  [in]ip地址
 * @return std::string .分ip地址字符串
 */
std::string sockaddr_ipv4(uint32_t addr) {
    char ip[16];
    const char* ret = inet_ntop(AF_INET, &addr, ip, 16);
    if(ret == nullptr) {
        return "";
    } else {
        return ip;
    }

    return "";
}

/**
 * @brief ipv6地址转换为字符串
 * 
 * @param addr  [in]ip地址
 * @return std::string :分ip地址字符串
 */
std::string sockaddr_ipv6(uint8_t* addr) {
    char ip[64];
    const char* ret = inet_ntop(AF_INET6, addr, ip, 64);
    if(ret == nullptr) {
        return "";
    } else {
        return ip;
    }
    
    return "";
}

/**
 * @brief 点分ipv4地址转换为32位网络字节序
 * 
 * @param host  [in]点分ip地址
 * @param addr  [out]32位ip地址
 * @return int32_t 若成功则为1，若输入不是有效的表达式则为0，若出错则为-1
 */
int32_t host2addr_ipv4(const char* host, struct in_addr& addr)
{
    return inet_pton(AF_INET, host, &addr);
}

/**
 * @brief :分ipv6地址转换为128位网络字节序
 * 
 * @param host  [in]:分ip地址
 * @param addr  [out]32位ip地址
 * @return int32_t 若成功则为1，若输入不是有效的表达式则为0，若出错则为-1
 */
int32_t host2addr_ipv6(const char* host, struct in6_addr& addr6)
{
    return inet_pton(AF_INET6, host, &addr6);
}

/**
 * @brief 内存mac地址转换为字符串
 * 
 * @param macAddress    [in]mac地址buf
 * @return std::string  :分mac地址字符串
 */
std::string MacBuftoStr(const unsigned char* mac_buf) {
    char str[32] = {0};
    sprintf(str, "%02X:%02X:%02X:%02X:%02X:%02X",
            mac_buf[0], mac_buf[1], mac_buf[2],
            mac_buf[3], mac_buf[4], mac_buf[5]);

    return str;
}

/**
 * @brief :分mac地址字符串转换为6字节buf
 * 
 * @param charArray     [in]:分mac地址字符串
 * @param macAddress    [out]6字节长度buf
 * @return uint32_t 成功返回chw::success,失败返回chw::fail
 */
uint32_t StrtoMacBuf(const char* charArray, unsigned char* macAddress) {
    if(isValidMacAddress(charArray) == false)
    {
        return chw::fail;
    }

    std::istringstream iss(charArray);
    int value;

    for (int i = 0; i < 6; i++) {
        iss >> std::hex >> value;
        macAddress[i] = static_cast<unsigned char>(value);
        iss.ignore(1, ':');
    }

    return chw::success;
}

bool isValidMacAddress(const std::string& mac) {
    // Regular expression for MAC address
    std::regex macRegex(
        "^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$"
    );

    // Check if the string matches the MAC address regex
    return std::regex_match(mac, macRegex);
}

#if defined(__linux__) || defined(__linux)
/**
 * @brief 判断字符串是否有效的mac地址
 * 
 * @param mac   [in]字符串
 * @return uint32_t 成功返回chw::success,失败返回chw::fail
 */
uint32_t is_valid_mac_addr(const char* mac) {
    int status;
    const char * pattern = "^([A-Fa-f0-9]{2}[-,:]){5}[A-Fa-f0-9]{2}$";
    const int cflags = REG_EXTENDED | REG_NEWLINE;

    char ebuf[128];
    regmatch_t pmatch[10];
    int nmatch = 10;
    regex_t reg;


    status = regcomp(&reg, pattern, cflags);//编译正则模式
    if(status != 0) {
        regerror(status, &reg, ebuf, sizeof(ebuf));
        PrintD( "error:regcomp fail: %s , pattern '%s' \n",ebuf, pattern);
        goto failed;
    }

    status = regexec(&reg, mac, nmatch, pmatch,0);//执行正则表达式和缓存的比较,
    if(status != 0) {
        regerror(status, &reg, ebuf, sizeof(ebuf));
        PrintD( "error:regexec fail: %s , mac:\"%s\" \n", ebuf, mac);
        goto failed;
    }

    //PrintD("[%s] match success.\n", __FUNCTION__);
    regfree(&reg);
    return chw::success;

failed:
    regfree(&reg);
    return chw::fail;
}
#endif// defined(__linux__) || defined(__linux)

std::string exePath(bool isExe /*= true*/) {
    char buffer[PATH_MAX * 2 + 1] = {0};
    int n = -1;
#if defined(_WIN32)
    n = GetModuleFileNameA(isExe?nullptr:(HINSTANCE)&__ImageBase, buffer, sizeof(buffer));
#elif defined(__MACH__) || defined(__APPLE__)
    n = sizeof(buffer);
    if (uv_exepath(buffer, &n) != 0) {
        n = -1;
    }
#elif defined(__linux__)
    n = readlink("/proc/self/exe", buffer, sizeof(buffer));
#endif

    std::string filePath;
    if (n <= 0) {
        filePath = "./";
    } else {
        filePath = buffer;
    }

#if defined(_WIN32)
    //windows下把路径统一转换层unix风格，因为后续都是按照unix风格处理的
    for (auto &ch : filePath) {
        if (ch == '\\') {
            ch = '/';
        }
    }
#endif //defined(_WIN32)

    return filePath;
}

std::string exeDir(bool isExe /*= true*/) {
    auto path = exePath(isExe);
    return path.substr(0, path.rfind('/') + 1);
}

std::string exeName(bool isExe /*= true*/) {
    auto path = exePath(isExe);
    return path.substr(path.rfind('/') + 1);
}

#define _strrchr_dot(str) strrchr(str, '.')
const char* suffixname(const char* filename) {
    const char* pos = _strrchr_dot(filename);
    return pos ? pos+1 : "";
}

// string转小写
std::string& strToLower(std::string& str) {
    transform(str.begin(), str.end(), str.begin(), towlower);
    return str;
}

// string转大写
std::string& strToUpper(std::string& str) {
    transform(str.begin(), str.end(), str.begin(), towupper);
    return str;
}

// string转小写
std::string strToLower(std::string&& str) {
    transform(str.begin(), str.end(), str.begin(), towlower);
    return std::move(str);
}

// string转大写
std::string strToUpper(std::string&& str) {
    transform(str.begin(), str.end(), str.begin(), towupper);
    return std::move(str);
}

/**
 * @brief 统计字符串中包含某字符的数量
 * 
 * @param msg		[in]字符串
 * @param c			[in]字符
 * @return 字符数量
 */
uint32_t count_char(const std::string& msg, char c)
{
	return std::count(msg.begin(), msg.end(), c);
}

/**
 * @brief 字符串分割
 * 
 * @param s        [in]输入字符串
 * @param delim    [in]分隔符
 * @return std::vector<std::string> 分割得到的子字符串集
 */
std::vector<std::string> split(const std::string &s, const char *delim) {
    std::vector<std::string> ret;
    size_t last = 0;
    auto index = s.find(delim, last);
    while (index != std::string::npos) {
        if (index - last > 0) {
            ret.push_back(s.substr(last, index - last));
        }
        last = index + strlen(delim);
        index = s.find(delim, last);
    }
    if (!s.size() || s.size() - last > 0) {
        ret.push_back(s.substr(last));
    }
    return ret;
}


/**
 * @brief 字符串分割
 * 
 * @param s        [in]输入字符串
 * @param delim    [in]分隔符
 * @return std::vector<spit_string> 分割得到的子字符串集结构体
 */
std::vector<spit_string> split_pos(const std::string &s, const char *delim) {
    std::vector<spit_string> ret;
    size_t last = 0;
    auto index = s.find(delim, last);
    while (index != std::string::npos) {
        if (index - last > 0) {
			spit_string sp;
			sp.uIndex = last;
			sp.str = s.substr(last, index - last);
            ret.push_back(std::move(sp));
        }
        last = index + strlen(delim);
        index = s.find(delim, last);
    }
    if (!s.size() || s.size() - last > 0) {
		spit_string sp;
		sp.uIndex = last;
		sp.str = s.substr(last);
        ret.push_back(std::move(sp));
    }
    return ret;
}

#ifdef _WIN32
#define CLEAR_COLOR 7
static const WORD LOG_CONST_TABLE[][3] = {
        {0x97, 0x09 , 'T'},//蓝底灰字，黑底蓝字，window console默认黑底
        {0xA7, 0x0A , 'D'},//绿底灰字，黑底绿字
        {0xB7, 0x0B , 'I'},//天蓝底灰字，黑底天蓝字
        {0xE7, 0x0E , 'W'},//黄底灰字，黑底黄字
        {0xC7, 0x0C , 'E'} };//红底灰字，黑底红字

bool SetConsoleColor2(WORD Color)
{
    HANDLE handle = GetStdHandle(STD_OUTPUT_HANDLE);
    if (handle == 0)
        return false;

    BOOL ret = SetConsoleTextAttribute(handle, Color);
    return(ret == TRUE);
}
#else
#define CLEAR_COLOR "\033[0m"
static const char *LOG_CONST_TABLE[][3] = {
        {"\033[44;37m", "\033[34m", "T"},	//blue
        {"\033[42;37m", "\033[32m", "D"},	//green
        {"\033[46;37m", "\033[36m", "I"},	//cyan
        {"\033[43;37m", "\033[33m", "W"},	//yellow
        {"\033[41;37m", "\033[31m", "E"}};	//red
#endif

typedef enum _COLOR_RULE {
	COLOR_ETH_TYPE,
	COLOR_NETWORK_HDR,
	COLOR_TRANSPORT_HDR,
	COLOR_JSON_COND,
	COLOR_NULL
}COLOR_RULE;

const uint32_t COLOR_LEN_RULE = sizeof(LOG_CONST_TABLE[2][1]);
const uint32_t COLOR_LEN_CLEAR= sizeof(CLEAR_COLOR);

/**
 * @brief 以16进制打印内存，两个字符表示一个字节，每一行固定字节数量，字节之间有空格
 * 
 * @param pBuff [in]内存
 * @param nLen  [in]内存长度
 */
void PrintBuffer(void* pBuff, unsigned int nLen, chw::ayz_info& ayz)
{
    if (NULL == pBuff || 0 == nLen)
    {
        return;
    }
#if defined(__linux__) || defined(__linux)
    // 输出到命令行使用颜色，输出到日志不使用颜色
    uint32_t net_hdrlen = 0;
    uint32_t trans_hdrlen = 0;
    if (gConfigCmd.save == nullptr)
    {
        // 计算网络层和传输层头长度
        if (ayz.ipver == IPV4)
        {
            net_hdrlen = ayz.ip4->ihl * 4;
        }
        else if (ayz.ipver == IPV6)
        {
            net_hdrlen = sizeof(chw::ip6hdr);
        }

        if (ayz.transport == tcp_trans)
        {
            trans_hdrlen = ayz.tcp->doff * 4;
        }
        else if (ayz.transport == udp_trans)
        {
            trans_hdrlen = 8;
        }
    }
#endif// defined(__linux__) || defined(__linux)
    static char* szHex_all = (char*)_RAM_NEW_(gConfigCmd.max * 4);

    const int nBytePerLine = 16;//每一行显示的字节数
    unsigned char* p = (unsigned char*)pBuff;

    _RAM_SET_(szHex_all, gConfigCmd.max * 4, 0, gConfigCmd.max * 4);
    uint32_t uIndex = 0;
    uint32_t uCount = 0;
    COLOR_RULE color = COLOR_NULL;

    for (uint32_t i = 0; i < nLen; ++i)
    {
#ifdef WIN32
        sprintf_s(&szHex_all[uIndex], 4, "%02x ", p[i]);// buff长度要多传入1个字节
#else
        snprintf(&szHex_all[uIndex], 4, "%02x ", p[i]); // buff长度要多传入1个字节
#endif
        uIndex += 3;//去掉每次拼接加的\0

        // 前八个和后八个字节中间加空格
        if (0 == ((i + 1) % (nBytePerLine / 2)))
        {
            szHex_all[uIndex] = ' ';
            uIndex++;
        }

        // 以16个字节为一行，进行打印
        if (0 == ((i + 1) % nBytePerLine))
        {
            szHex_all[uIndex] = '\n';
            uIndex++;
        }

        //设置条件跳出打印
        uCount++;
        if (uCount >= gConfigCmd.max)
        {
#if defined(__linux__) || defined(__linux)
            if (color != COLOR_NULL)
            {
                memcpy(&szHex_all[uIndex], CLEAR_COLOR, COLOR_LEN_CLEAR);
                color = COLOR_NULL;
                uIndex += 4;
            }
#endif// defined(__linux__) || defined(__linux)
            szHex_all[uIndex++] = '.';
            szHex_all[uIndex++] = '.';
            szHex_all[uIndex++] = '.';

            break;
        }
#if defined(__linux__) || defined(__linux)
        if (gConfigCmd.save == nullptr)
        {
            // JSON匹配条件添加颜色规则，优先级最高
            if (i == ayz.json_start - 1)
            {
                if (color != COLOR_NULL)
                {
                    memcpy(&szHex_all[uIndex], CLEAR_COLOR, COLOR_LEN_CLEAR);
                    color = COLOR_NULL;
                    uIndex += 4;
                }
                memcpy(&szHex_all[uIndex], LOG_CONST_TABLE[4][1], COLOR_LEN_RULE);
                uIndex += 5;
                color = COLOR_JSON_COND;
            }
            if (i == ayz.json_end)
            {

                if (color == COLOR_JSON_COND)
                {
                    memcpy(&szHex_all[uIndex], CLEAR_COLOR, COLOR_LEN_CLEAR);
                    color = COLOR_NULL;
                    uIndex += 4;
                }
                }
            // ETH类型，固定2字节
            if (i == 11)
            {
                if (color == COLOR_NULL)
                {
                    memcpy(&szHex_all[uIndex], LOG_CONST_TABLE[2][1], COLOR_LEN_RULE);

                    uIndex += 5;
                    color = COLOR_ETH_TYPE;
                }
            }
            if (i == 13)
            {
                if (color == COLOR_ETH_TYPE)
                {
                    memcpy(&szHex_all[uIndex], CLEAR_COLOR, COLOR_LEN_CLEAR);
                    color = COLOR_NULL;
                    uIndex += 4;
                }
            }

            // 网络层头部添加颜色规则
            if (i >= 13 && i < 13 + net_hdrlen)
            {
                if (color == COLOR_NULL)
                {
                    memcpy(&szHex_all[uIndex], LOG_CONST_TABLE[0][1], COLOR_LEN_RULE);

                    uIndex += 5;
                    color = COLOR_NETWORK_HDR;
                }
            }
            if (i == 13 + net_hdrlen)
            {
                if (color == COLOR_NETWORK_HDR)
                {
                    memcpy(&szHex_all[uIndex], CLEAR_COLOR, COLOR_LEN_CLEAR);
                    color = COLOR_NULL;
                    uIndex += 4;
                }
                }

            // 传输层头部添加颜色规则
            if (i == 13 + net_hdrlen)
            {
                if (color == COLOR_NULL)
                {
                    memcpy(&szHex_all[uIndex], LOG_CONST_TABLE[1][1], COLOR_LEN_RULE);

                    uIndex += 5;
                    color = COLOR_NETWORK_HDR;
                }
            }
            if (i == 13 + net_hdrlen + trans_hdrlen)
            {
                if (color == COLOR_NETWORK_HDR)
                {
                    memcpy(&szHex_all[uIndex], CLEAR_COLOR, COLOR_LEN_CLEAR);
                    color = COLOR_NULL;
                    uIndex += 4;
                }
            }

            }
#endif// defined(__linux__) || defined(__linux)
    }
    szHex_all[uIndex] = '\0';

    PrintD("%s\n", szHex_all);
}

/**
 * @brief 判断字符串是否为空
 * @param value [in]入参字符串
 * @return true字符串为空，false字符串不为空
 */
bool StrIsNull(const char *value)
{
    if(!value || value[0] == '\0')
    {
        return true;
    }

    return false;
}

/**
 * @brief 将16进制字符转换为10进制
 * @param hex   [in]16进制字符
 * @return      转换后的10进制
 */
unsigned char HextoInt(unsigned char hex)
{
    const int DEC = 10;
    if(('0' <= hex) && ('9' >= hex))
    {
        //减去'0'转换为整数
        return (hex - '0');
    }
    else if(('A' <= hex) && ('F' >= hex))
    {
        return (hex - 'A' + DEC);
    }
    else if(('a' <= hex) && ('f' >= hex))
    {
        return (hex - 'a' + DEC);
    }

    return 0;
}

/**
 * @brief 16进制表示字符串转换成16进制内存buf ("0080"字符串 -> 查看内存是0080)
 * @param value [in]要转换的字符串
 * @return      返回转换的结果
 */
std::string StrHex2StrBuf(const char *value)
{
    if(StrIsNull(value))
    {
        return "";
    }

    //2个字符表示一个16进制数
    int len = strlen(value);
    if(len % 2 != 0)
    {
        return "";
    }

    std::string result(len / 2, '\0');
    for(int i = 0; i < len; i += 2)
    {
        result[i / 2] = HextoInt(value[i]) * 16 + HextoInt(value[i + 1]);
    }

    return result;
}

std::string StrHex2StrBuf(const char *value, char wild_card)
{
    if(StrIsNull(value))
    {
        return "";
    }

    //2个字符表示一个16进制数
    int len = strlen(value);
    if(len % 2 != 0)
    {
        return "";
    }

    std::string result(len / 2, '\0');
    for(int i = 0; i < len; i += 2)
    {
        if(value[i] == wild_card)
        {
            result[i / 2] = wild_card;
        }
        else
        {
            result[i / 2] = HextoInt(value[i]) * 16 + HextoInt(value[i + 1]);
        }
        
    }

    return result;
}

/**
 * @brief 将内存buffer转换成16进制形式字符串(内存16进制0800->"0800"字符串)
 * @param value [in]buffer
 * @param len   [in]长度
 * @return      转换后的字符串
 */
std::string HexBuftoString(const unsigned char *value, int len)
{
    std::string result(len * 2, '\0');
    for(int i = 0;i < len; ++i)
    {
        char *buff = (char *)result.data() + i * 2;
        sprintf(buff ,"%02x", value[i]);
    }

    return std::move(result);
}

/**
 * @brief 替换字符串中的子串
 * 
 * @param str   [in]字符串
 * @param find  [in]子串
 * @param rep   [in]替换为的串
 * @return std::string 替换后的字符串
 */
std::string replaceAll(const std::string& str, const std::string& find, const std::string& rep)
{
    std::string::size_type pos = 0;
    std::string::size_type a = find.size();
    std::string::size_type b = rep.size();

    std::string res(str);
    while ((pos = res.find(find, pos)) != std::string::npos) {
        res.replace(pos, a, rep);
        pos += b;
    }
    return res;
}

/**
 * @brief 取4字节整数的低4位，高28位补0，示例:100(...0110 0100)——>4(...0000 0100)
 * 
 * @param num	[in]输入整数
 * @return 	    转换后的整数
 */
int32_t int32_lowfour(int32_t num)
{
	return num & 0xF;
}

/**
 * @brief 取4字节整数的高4位，低28位补0
 * 
 * @param num	[in]输入整数
 * @return 	    转换后的整数
 */
int32_t int32_highfour(int32_t num)
{
	return ((num >> 28) & 0xF);
}

/**
 * @brief 取2字节整数的低4位，高12位补0
 * 
 * @param num	[in]输入整数
 * @return 	    转换后的整数
 */
int16_t int16_lowfour(int16_t num)
{
	return num & 0xF;
}

/**
 * @brief 取2字节整数的高4位，低12位补0
 * 
 * @param num	[in]输入整数
 * @return 	    转换后的整数
 */
int16_t int16_highfour(int16_t num)
{
    return ((num >> 12) & 0xF);
}

/**
 * @brief 取1字节整数的低4位，高4位补0
 * 
 * @param num	[in]输入整数
 * @return 	    转换后的整数
 */
int8_t int8_lowfour(int8_t num)
{
    return num & 0xF;
}

/**
 * @brief 取1字节整数的高4位，低4位补0
 * 
 * @param num	[in]输入整数
 * @return 	    转换后的整数
 */
int8_t int8_highfour(int8_t num)
{
    return ((num >> 4) & 0xF);
}


#if defined(_WIN32)
void sleep(int second) {
    Sleep(1000 * second);
}
void usleep(int micro_seconds) {
    this_thread::sleep_for(std::chrono::microseconds(micro_seconds));
}

int gettimeofday(struct timeval* tp, void* tzp) {
    auto now_stamp = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    tp->tv_sec = (decltype(tp->tv_sec))(now_stamp / 1000000LL);
    tp->tv_usec = now_stamp % 1000000LL;
    return 0;
}

const char* strcasestr(const char* big, const char* little) {
    string big_str = big;
    string little_str = little;
    strToLower(big_str);
    strToLower(little_str);
    auto pos = strstr(big_str.data(), little_str.data());
    if (!pos) {
        return nullptr;
    }
    return big + (pos - big_str.data());
}

int vasprintf(char** strp, const char* fmt, va_list ap) {
    // _vscprintf tells you how big the buffer needs to be
    int len = _vscprintf(fmt, ap);
    if (len == -1) {
        return -1;
    }
    size_t size = (size_t)len + 1;
    char* str = (char*)malloc(size);
    if (!str) {
        return -1;
    }
    // _vsprintf_s is the "secure" version of vsprintf
    int r = vsprintf_s(str, len + 1, fmt, ap);
    if (r == -1) {
        free(str);
        return -1;
    }
    *strp = str;
    return r;
}

int asprintf(char** strp, const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int r = vasprintf(strp, fmt, ap);
    va_end(ap);
    return r;
}

#endif //WIN32

} /* namespace chw */
