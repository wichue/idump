#include "CmdLineParse.h"
#include <getopt.h>// for getopt_long
#include <stdlib.h>// for exit
#include <stdio.h>// for printf

namespace chw {

INSTANCE_IMP(CmdLineParse)

int CmdLineParse::parse_arguments(int argc, char **argv)
{
    static struct option longopts[] = 
    {
        {"file", required_argument, NULL, 'f'},
        {"version", no_argument, NULL, 'v'},
        {"port", required_argument, NULL, 'p'},
        {NULL, 0, NULL, 0}
    };
    int flag;
   
    while ((flag = getopt_long(argc, argv, "f:p:", longopts, NULL)) != -1) {
        switch (flag) {
            case 'f':
            printf("file name:%s\n", optarg);
                break;
            case 'p':
            printf("p:%d\n", atoi(optarg));
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