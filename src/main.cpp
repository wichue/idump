#include <setjmp.h>// for setjmp
#include <stdio.h>// for printf
#include <stdlib.h>// for exit
#include <unistd.h>//for usleep
#include <signal.h>//for SIG_DFL

#include "CmdLineParse.h"
#include "SignalCatch.h"
#include "BackTrace.h"
#include "Logger.h"
#include "GlobalValue.h"
#include "PcapParse.h"

//捕获ctrl+c
void sigend_handler_abort(int sig)
{
    printf("catch abort signal:%d,exit now.\n",sig);
    exit(0);
}

//捕获段错误
void sigend_handler_crash(int sig)
{
    printf("catch crash signal:%d,exit now.\n",sig);
    chw_assert();
}

int main(int argc, char **argv)
{
    chw::SignalCatch::Instance().CustomAbort(sigend_handler_abort);
    chw::SignalCatch::Instance().CustomCrash(sigend_handler_crash);
    chw::CmdLineParse::Instance().parse_arguments(argc,argv);

    // 设置日志系统
    if(gConfigCmd.save == nullptr)
    {
        chw::Logger::Instance().add(std::make_shared<chw::ConsoleChannel>());
    }
    else
    {
        std::shared_ptr<chw::FileChannelBase> fc = std::make_shared<chw::FileChannelBase>();
        if(!fc->setPath(gConfigCmd.save))
        {
            printf("log file path invalid,path=%s\n",gConfigCmd.save);
            exit(1);
        }
        chw::Logger::Instance().add(fc);
    }
    chw::Logger::Instance().setWriter(std::make_shared<chw::AsyncLogWriter>());

    PcapParse pp;
    pp.parse(gConfigCmd.file);

    chw::SignalCatch::Instance().CustomAbort(SIG_DFL);
    chw::SignalCatch::Instance().CustomCrash(SIG_DFL);
    
    return 0;
}