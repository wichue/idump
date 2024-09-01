#ifndef UTIL_UTIL_H_
#define UTIL_UTIL_H_

#include <memory>// for std::shared_ptr
#include <vector>

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
 * @brief Get the Thread Name object
 * 
 * @return std::string 
 */
std::string getThreadName();

/**
 * 根据unix时间戳获取本地时间
 * @param sec unix时间戳
 * @return tm结构体
 */
struct tm getLocalTime(time_t sec);

/**
 * 获取时间字符串
 * @param fmt 时间格式，譬如%Y-%m-%d %H:%M:%S
 * @return 时间字符串
 */
std::string getTimeStr(const char *fmt,time_t time = 0);

//判断是否为ip
bool isIP(const char *str);
//字符串是否以xx开头
bool start_with(const std::string &str, const std::string &substr);
//字符串是否以xx结尾
bool end_with(const std::string &str, const std::string &substr);
std::string exePath(bool isExe = true);
std::string exeDir(bool isExe = true);
std::string exeName(bool isExe = true);
std::vector<std::string> split(const std::string& s, const char *delim);

/**
 * @brief 以16进制打印内存
 * 
 * @param pBuff 内存
 * @param nLen  内存长度
 */
void PrintBuffer(void* pBuff, unsigned int nLen);


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