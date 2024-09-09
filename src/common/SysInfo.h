#ifndef __SYS_INFO_H
#define __SYS_INFO_H

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

namespace chw {

    /**
     * @brief 计算磁盘总大小和可用大小，单位kb
     * 
     * @param totalsize     总大小
     * @param availableDisk 可用大小
     * @return uint32_t 
     */
    uint32_t CptDisk(uint64_t& totalsize, uint64_t& availableDisk);

    /**
     * @brief 计算内存大小，单位kb
     * 
     * @param MemTotal      总内存
     * @param MemAvailable  可用内存
     * @return uint32_t 
     */
    uint32_t CptMemory(uint64_t& MemTotal, uint64_t& MemAvailable);

}// namespace chw

#endif //__SYS_INFO_H