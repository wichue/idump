#include "util.h"
#include <assert.h>
#include <pthread.h>
#include <limits.h>//for PATH_MAX
#include <unistd.h>
#include <string.h>
#include <string>
#include <time.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/types.h>
#include <regex.h>

#include "local_time.h"
#include "Logger.h"
#include "MemoryHandle.h"
#include "GlobalValue.h"

namespace chw {

static std::string limitString(const char *name, size_t max_size) {
    std::string str = name;
    if (str.size() + 1 > max_size) {
        auto erased = str.size() + 1 - max_size + 3;
        str.replace(5, erased, "...");
    }
    return str;
}

void setThreadName(const char *name) {
    assert(name);
#if defined(__linux) || defined(__linux__) || defined(__MINGW32__)
    pthread_setname_np(pthread_self(), limitString(name, 16).data());
#elif defined(__MACH__) || defined(__APPLE__)
    pthread_setname_np(limitString(name, 32).data());
#elif defined(_MSC_VER)
    // SetThreadDescription was added in 1607 (aka RS1). Since we can't guarantee the user is running 1607 or later, we need to ask for the function from the kernel.
    using SetThreadDescriptionFunc = HRESULT(WINAPI * )(_In_ HANDLE hThread, _In_ PCWSTR lpThreadDescription);
    static auto setThreadDescription = reinterpret_cast<SetThreadDescriptionFunc>(::GetProcAddress(::GetModuleHandle("Kernel32.dll"), "SetThreadDescription"));
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

struct tm getLocalTime(time_t sec) {
    struct tm tm;
#ifdef _WIN32
    localtime_s(&tm, &sec);
#else
    no_locks_localtime(&tm, sec);
#endif //_WIN32
    return tm;
}

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

int32_t host2addr_ipv4(const char* host, struct in_addr& addr)
{
    return inet_pton(AF_INET, host, &addr);
}

int32_t host2addr_ipv6(const char* host, struct in6_addr& addr6)
{
    return inet_pton(AF_INET6, host, &addr6);
}

std::string MacBuftoStr(const unsigned char* mac_buf) {
    char str[32] = {0};
    sprintf(str, "%02X:%02X:%02X:%02X:%02X:%02X",
            mac_buf[0], mac_buf[1], mac_buf[2],
            mac_buf[3], mac_buf[4], mac_buf[5]);

    return str;
}

uint32_t StrtoMacBuf(const char* charArray, unsigned char* macAddress) {
    if(is_valid_mac_addr(charArray) == chw::fail)
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

#ifdef _WIN32
#define CLEAR_COLOR 7
static const WORD LOG_CONST_TABLE[][3] = {
        {0x97, 0x09 , 'T'},//蓝底灰字，黑底蓝字，window console默认黑底
        {0xA7, 0x0A , 'D'},//绿底灰字，黑底绿字
        {0xB7, 0x0B , 'I'},//天蓝底灰字，黑底天蓝字
        {0xE7, 0x0E , 'W'},//黄底灰字，黑底黄字
        {0xC7, 0x0C , 'E'} };//红底灰字，黑底红字

bool SetConsoleColor(WORD Color)
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

void PrintBuffer(void* pBuff, unsigned int nLen, chw::ayz_info& ayz)
{
    if (NULL == pBuff || 0 == nLen)
    {
        return;
    }

	// 输出到命令行使用颜色，输出到日志不使用颜色
	uint32_t net_hdrlen = 0;
	uint32_t trans_hdrlen = 0;
	if(gConfigCmd.save == nullptr)
	{
		// 计算网络层和传输层头长度
		if(ayz.ipver == IPV4)
		{
			net_hdrlen = ayz.ip4->ihl * 4;
		}
		else if(ayz.ipver == IPV6)
		{
			net_hdrlen = sizeof(chw::ip6hdr);
		}

		if(ayz.transport == tcp_trans)
		{
			trans_hdrlen = ayz.tcp->doff * 4;
		}
		else if(ayz.transport == udp_trans)
		{
			trans_hdrlen = 8;
		}
	}

    static char* szHex_all = (char*)_RAM_NEW_(gConfigCmd.max * 4);

    const int nBytePerLine = 16;//每一行显示的字节数
    unsigned char* p = (unsigned char*)pBuff;

    _RAM_SET_(szHex_all,gConfigCmd.max * 4,0,gConfigCmd.max * 4);
    uint32_t uIndex = 0;
    uint32_t uCount = 0;
	uint32_t uPrinted = 0;

    for (uint32_t i=0; i<nLen; ++i)
    {
#ifdef WIN32
        sprintf_s(&szHex_all[uIndex], 4, "%02x ", p[i]);// buff长度要多传入1个字节
#else
        snprintf(&szHex_all[uIndex], 4, "%02x ", p[i]); // buff长度要多传入1个字节
#endif
        uIndex += 3;//去掉每次拼接加的\0
        
		// 前八个和后八个字节中间加空格
        if (0 == ((i+1) % (nBytePerLine/2)))
        {
            szHex_all[uIndex] = ' ';
            uIndex++;
        }

        // 以16个字节为一行，进行打印
        if (0 == ((i+1) % nBytePerLine))
        {
            szHex_all[uIndex] = '\n';
            uIndex++;
        }

        //设置条件跳出打印
        uCount++;
		if(uCount >= gConfigCmd.max)
        {
            szHex_all[uIndex++] = '.';
            szHex_all[uIndex++] = '.';
            szHex_all[uIndex++] = '.';
            break;
        }

		// 输出到命令行使用颜色，输出到日志不使用颜色
    	if(gConfigCmd.save == nullptr)
		{
			// 先输出目的MAC和源MAC，固定12字节
			if(i == 11)
			{
				uPrinted = uIndex;
    			PrintNCR("%s", szHex_all);
			}
			// 网络层协议类型固定2字节
			if(i == 13)
			{
				PrintNCR("%s",LOG_CONST_TABLE[2][1]);
    			PrintNCR("%s", szHex_all + uPrinted);
				PrintNCR("%s", CLEAR_COLOR);
				uPrinted = uIndex;
			}
			// 网络层协议头
			if(i == 13 + net_hdrlen)
			{
				PrintNCR("%s",LOG_CONST_TABLE[0][1]);
    			PrintNCR("%s", szHex_all + uPrinted);
				PrintNCR("%s", CLEAR_COLOR);
				uPrinted = uIndex;
			}
			// 传输层协议头
			if(i == 13 + net_hdrlen + trans_hdrlen)
			{
				PrintNCR("%s",LOG_CONST_TABLE[1][1]);
    			PrintNCR("%s", szHex_all + uPrinted);
				PrintNCR("%s", CLEAR_COLOR);
				uPrinted = uIndex;
			}
			// json匹配条件,只对应用层的数据使用颜色
			uint32_t pre_app_len = 14 + net_hdrlen + trans_hdrlen;// 应用层数据前面的长度（以太头 + 网络层头 + 传输层头的长度）
//			PrintD("json_start=%u,json_end=%u,i=%u,pre_app_len=%u",ayz.json_start,ayz.json_end,i,pre_app_len);
				if(i == ayz.json_end
				&& ayz.json_start > pre_app_len - 1)
				{
					std::string msg(szHex_all,ayz.json_start - pre_app_len - 1);
					uPrinted += uPrinted + ayz.json_start - pre_app_len - 1;
	    			PrintNCR("%s", msg.c_str());
					PrintNCR("%s",LOG_CONST_TABLE[4][1]);
	    			PrintNCR("%s", szHex_all + uPrinted);
					PrintNCR("%s", CLEAR_COLOR);
					uPrinted = uIndex;
				}
		}
    }
    szHex_all[uIndex] = '\0';

    PrintD("%s", szHex_all + uPrinted);
}

bool StrIsNull(const char *value)
{
    if(!value || value[0] == '\0')
    {
        return true;
    }

    return false;
}

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


int32_t int32_lowfour(int32_t num)
{
	return num & 0xF;
}

int32_t int32_highfour(int32_t num)
{
	return ((num >> 28) & 0xF);
}

int16_t int16_lowfour(int16_t num)
{
	return num & 0xF;
}

int16_t int16_highfour(int16_t num)
{
    return ((num >> 12) & 0xF);
}

int8_t int8_lowfour(int8_t num)
{
    return num & 0xF;
}

int8_t int8_highfour(int8_t num)
{
    return ((num >> 4) & 0xF);
}

} /* namespace chw */
