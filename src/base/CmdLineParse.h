#ifndef        __CMD_LINE_PARSE_H
#define        __CMD_LINE_PARSE_H

#include "util.h"

namespace chw {

class CmdLineParse {
public:
    CmdLineParse() = default;
    ~CmdLineParse() = default;

    static CmdLineParse &Instance();

    int32_t parse_arguments(int argc, char **argv);
    int32_t printf_help();
private:
	void help();
	void version();
};

}//namespace chw
#endif //__CMD_LINE_PARSE_H
