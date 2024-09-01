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

#include "local_time.h"
#include "Logger.h"

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

void PrintBuffer(void* pBuff, unsigned int nLen)
{
    if (NULL == pBuff || 0 == nLen)
    {
        return;
    }

    const int nBytePerLine = 16;
    unsigned char* p = (unsigned char*)pBuff;
    char szHex[3*nBytePerLine+1] = {0};

    // printf("-----------------begin-------------------\n");
    for (unsigned int i=0; i<nLen; ++i)
    {
        int idx = 3 * (i % nBytePerLine);
        if (0 == idx)
        {
            memset(szHex, 0, sizeof(szHex));
        }
#ifdef WIN32
        sprintf_s(&szHex[idx], 4, "%02x ", p[i]);// buff长度要多传入1个字节
#else
        snprintf(&szHex[idx], 4, "%02x ", p[i]); // buff长度要多传入1个字节
#endif
        
        // 以16个字节为一行，进行打印
        if (0 == ((i+1) % nBytePerLine))
        {
            PrintD("%s", szHex);
        }
    }

    // 打印最后一行未满16个字节的内容
    if (0 != (nLen % nBytePerLine))
    {
        PrintD("%s", szHex);
    }

    // printf("------------------end-------------------\n");
}

} /* namespace chw */