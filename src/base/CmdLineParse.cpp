#include "CmdLineParse.h"
#include <getopt.h>// for getopt_long
#include <stdlib.h>// for exit
#include <stdio.h>// for printf

#include "GlobalValue.h"

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
        {"more", no_argument, NULL, 'm'},
        {NULL, 0, NULL, 0}
    };
    int flag;
   
    while ((flag = getopt_long(argc, argv, "f:p:", longopts, NULL)) != -1) {
        switch (flag) {
            case 'f':
                printf("file name:%s\n", optarg);
                gConfigCmd.file = optarg;
                break;
            case 'p':
                printf("p:%d\n", atoi(optarg));
                break;
            case 's':
                gConfigCmd.save = optarg;
                printf("save name:%s\n", gConfigCmd.save);
                break;
            case 'm':
                gConfigCmd.more = true;
                break;
                
       
            default:
                // fprintf(stderr, "\n");
                // usage();
                exit(1);
        }
    }

    return 0;
}

}//namespace chw