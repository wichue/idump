// Copyright (c) 2024 The idump project authors. SPDX-License-Identifier: MIT.
// This file is part of idump(https://github.com/wichue/idump).

#include "CmdLineParse.h"
#ifdef WIN32
#include "getopt.h"
#else
#include <getopt.h>// for getopt_long
#endif

#include <stdlib.h>// for exit
#include <stdio.h>// for printf

#include "GlobalValue.h"
#include "Logger.h"

namespace chw {

INSTANCE_IMP(CmdLineParse)

/**
 * @brief 解析命令行参数
 * 
 * @param argc		[in]参数数量
 * @param argv		[in]参数指针
 * @return uint32_t 成功返回chw::success,失败返回chw::fail
 */
int CmdLineParse::parse_arguments(int argc, char **argv)
{
    static struct option longopts[] = 
    {
        {"help", no_argument, NULL, 'h'},
        {"version", no_argument, NULL, 'v'},
        {"file", required_argument, NULL, 'f'},
        {"save", required_argument, NULL, 's'},
        {"filter", required_argument, NULL, 'g'},
        {"compare", no_argument, NULL, 'c'},
        {"max", required_argument, NULL, 'm'},
        {"json", required_argument, NULL, 'j'},
        {"file1", required_argument, NULL, 'a'},
        {"file2", required_argument, NULL, 'b'},
        {"start", required_argument, NULL, 'k'},
        {"end", required_argument, NULL, 'l'},
        {NULL, 0, NULL, 0}
    };
    int flag;
   
    while ((flag = getopt_long(argc, argv, "hvf:s:g:m:j:ca:b:k:l:", longopts, NULL)) != -1) {
        switch (flag) {
            case 'f':
                gConfigCmd.file = optarg;
                break;
            case 's':
                gConfigCmd.save = optarg;
                break;
            case 'j':
                gConfigCmd.json = optarg;
                break;
            case 'm':
                gConfigCmd.max = atoi(optarg);
                break;
            case 'g':
                gConfigCmd.filter = optarg;
                break;
            case 'c':
                gConfigCmd.bCmp = true;
                break;
            case 'a':
                gConfigCmd.file1 = optarg;
                break;
            case 'b':
                gConfigCmd.file2 = optarg;
                break;
            case 'k':
                gConfigCmd.start = atoi(optarg);
                break;
            case 'l':
                gConfigCmd.end = atoi(optarg);
                break;
            case 'h':
				help();
                break;
            case 'v':
				version();
				exit(0);
                break;
                
       
            default:
				printf("Incorrect parameter option, --help for help.\n");
                exit(1);
        }
    }

    return chw::fail;
}

/**
 * @brief 打印帮助
 */
void CmdLineParse::help()
{
	version();

	printf(
			"	--help(-h) for help.\n"
			"	--version(-v) for version info.\n\n"

			"	--file(-f), pcap file to parse,default model,without -c.\n"
			"	--json(-j), json match condition,from file.\n"
			"	--filter(-f), cmd line filter condition,like wireshark.\n"
			"	--save(-s), log output to file,without this option,log output to console.\n"
			"	--max(-m), print msg by bytes up to max,without this option or 0,do not print msg details.\n\n"

			"	--compare(-c),compare by byte,must option:file1,file2,can use --json and --filter conditions.\n"
			"	--file1(-a),one of pcap file for compare.\n"
			"	--file2(-b),one of pcap file for compare.\n"
			"	--start(-k), compare model,the begin offset of msg,without this option begin offset is 0.\n"
			"	--end(-l), compare model,the end offset of msg,without this option end offset is 0.\n"
			);

	exit(0);
}

/**
 * @brief 打印版本
 */
void CmdLineParse::version()
{
#ifdef WIN32
	printf("idump version 1.0.0 for windows.  Welcome to visit url: https://github.com/wichue/idump\n");
#else
	printf("idump version 1.0.0 for linux.  Welcome to visit url: https://github.com/wichue/idump\n");
#endif
}

}//namespace chw
