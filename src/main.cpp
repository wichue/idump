#include <setjmp.h>// for setjmp
#include <stdio.h>// for printf
#include <stdlib.h>// for exit
#include <unistd.h>//for usleep
#include <signal.h>//for SIG_DFL

#include "CmdLineParse.h"
#include "SignalCatch.h"
#include "BackTrace.h"

//捕获ctrl+c
void sigend_handler(int sig)
{
    printf("catch abort signal:%d,exit now.\n",sig);
    exit(0);
}

//捕获段错误
void sigend_handler2(int sig)
{
    printf("catch crash signal:%d,exit now.\n",sig);
    chw_assert();
}

int main(int argc, char **argv)
{
    chw::CmdLineParse::Instance().parse_arguments(argc,argv);
    chw::SignalCatch::Instance().CustomAbort(sigend_handler);
    chw::SignalCatch::Instance().CustomCrash(sigend_handler2);


    //主业务
    while(1)
    {
        usleep(1000*1000);
        printf("loop\n");
    }

    chw::SignalCatch::Instance().CustomAbort(SIG_DFL);
    chw::SignalCatch::Instance().CustomCrash(SIG_DFL);
    
    return 0;
}