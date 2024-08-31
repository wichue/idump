#ifndef        __SIGNAL_CATCH_H
#define        __SIGNAL_CATCH_H

#include "util.h"

namespace chw {

class SignalCatch {
public:
    SignalCatch();
    ~SignalCatch();

    static SignalCatch &Instance();

    /**
     * @brief catch SIGINT,SIGTERM,SIGHUP
     * 
     */
    void CustomAbort(void (*handler)(int));

    /**
     * @brief catch SIGSEGV 
     * 
     * @param handler 
     */
    void CustomCrash(void (*handler)(int));
};



}//namespace chw
#endif // __SIGNAL_CATCH_H