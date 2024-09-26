#include "CmdLineParse.h"
#include <getopt.h>// for getopt_long
#include <stdlib.h>// for exit
#include <stdio.h>// for printf

#include "GlobalValue.h"
#include "Logger.h"

namespace chw {

INSTANCE_IMP(CmdLineParse)

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
        {"max", required_argument, NULL, 'n'},
        {"json", required_argument, NULL, 'j'},
        {"file1", required_argument, NULL, 'a'},
        {"file2", required_argument, NULL, 'b'},
        {"start", required_argument, NULL, 'k'},
        {"end", required_argument, NULL, 'l'},
        {NULL, 0, NULL, 0}
    };
    int flag;
   
    while ((flag = getopt_long(argc, argv, "hvf:s:g:mn:j:ca:b:k:l:", longopts, NULL)) != -1) {
        switch (flag) {
            case 'f':
                gConfigCmd.file = optarg;
                break;
            case 'p':
                PrintD("p:%d\n", atoi(optarg));
                break;
            case 's':
                gConfigCmd.save = optarg;
                break;
            case 'j':
                gConfigCmd.json = optarg;
                break;
            case 'n':
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
                
       
            default:
                // fprintf(stderr, "\n");
                // usage();
                exit(1);
        }
    }

    return 0;
}

int32_t CmdLineParse::printf_help()
{
    return 0;
}

}//namespace chw
