#include "SignalCatch.h"
#include <signal.h>

namespace chw {

INSTANCE_IMP(SignalCatch)

SignalCatch::SignalCatch()
{
    /* Ignore SIGPIPE to simplify error handling */
    signal(SIGPIPE, SIG_IGN);
}

SignalCatch::~SignalCatch()
{
    signal(SIGPIPE, SIG_DFL);// 管道信号恢复默认动作
}

void SignalCatch::CustomAbort(void (*handler)(int))
{
#ifdef SIGINT// 由应用程序用户生成的交互式注意信号，Ctrl+c
    signal(SIGINT, handler);
#endif
#ifdef SIGTERM// 请求中止进程，kill命令缺省发送
    signal(SIGTERM, handler);
#endif
#ifdef SIGHUP// 当terminal 被disconnect时候发送
    signal(SIGHUP, handler);
#endif
}

void SignalCatch::CustomCrash(void (*handler)(int))
{
    signal(SIGSEGV, handler);
}


}//namespace chw