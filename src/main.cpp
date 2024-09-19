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
#include "JsonCondition.h"
#include "SysInfo.h"
#include "FilterCondition.h"

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
/**
 * @brief 
 * 功能：
 * 1、抓包报文概要和报文16进制内容打印到日志文件或控制台。
 * 2、可设置报文16进制内容打印的最大长度。
 * 3、可根据传统的报文长度、协议类型、IP、port等过滤报文。
 * 4、高级过滤：指定报文起点字节数，要比对的报文16进制段，过滤出该位置包含该16进制段的报文。
 * 5、高级过滤选项从JOSN文件读取，过滤多个字段，并标记每个报文的描述。
 * 6、两个抓包文件进行逐字节比较，检查丢包、错包等问题，比较时可忽略指定字节数量的前缀和后缀。
 * @param argc 
 * @param argv 
 * @return int 
 */
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

	if(gConfigCmd.filter != nullptr)
	{
		FilterCondition fc;
		fc.ParseFilter(gConfigCmd.filter);
	}

    if(gConfigCmd.json != nullptr)
    {
        JsonCondition jc;
        jc.ParseJson(gConfigCmd.json);
    }

    if(gConfigCmd.file != nullptr)
    {
        PcapParse pp;
        pp.parse_file(gConfigCmd.file);
    }
    else
    {
        chw::CmdLineParse::Instance().printf_help();
    }


    chw::SignalCatch::Instance().CustomAbort(SIG_DFL);
    chw::SignalCatch::Instance().CustomCrash(SIG_DFL);
    
    return 0;
}
