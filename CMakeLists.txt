cmake_minimum_required(VERSION 2.8) #设置cmake最低版本
project("idump")	#设置项目名称
SET(PREFIX ${CMAKE_CURRENT_SOURCE_DIR})#设置普通变量，CMAKE_CURRENT_SOURCE_DIR为当前cmake文件目录
SET(BINDIR /usr/bin)
message (">>> pwd = ${PREFIX}")#打印变量

# 添加依赖头文件目录
SET(INCDIR
${PREFIX}/src
    ${PREFIX}/src/base
    ${PREFIX}/src/pcap
    ${PREFIX}/src/common
)
INCLUDE_DIRECTORIES(${INCDIR})

SET(SRCS
    ${PREFIX}/src/main.cpp
    ${PREFIX}/src/base/CmdLineParse.cpp
    ${PREFIX}/src/base/SignalCatch.cpp
    ${PREFIX}/src/base/BackTrace.cpp
    ${PREFIX}/src/base/util.cpp
    ${PREFIX}/src/base/Logger.cpp
    ${PREFIX}/src/base/File.cpp
    ${PREFIX}/src/base/local_time.cpp
    ${PREFIX}/src/GlobalValue.cpp
    ${PREFIX}/src/pcap/PcapParse.cpp
    ${PREFIX}/src/pcap/JsonCondition.cpp
	${PREFIX}/src/pcap/FilterCondition.cpp
    ${PREFIX}/src/pcap/PcapCompare.cpp
    ${PREFIX}/src/common/getopt.c
)

SET(SRCS ${SRCS}
)

#添加依赖库
SET(LIB_SO
    -ldl
    -lpthread
)

SET(RUN_MAIN "idump")
#设置C语言编译选项
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g")
#设置C++编译选项
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -std=c++11 -march=native -Wall")

# 添加可执行文件，并配相关文件
ADD_EXECUTABLE(${RUN_MAIN} ${SRCS})

TARGET_LINK_LIBRARIES(${RUN_MAIN} ${LIB_SO})#添加依赖库


# 安装可执行文件到指定位置，并指定权限
INSTALL(TARGETS ${RUN_MAIN} DESTINATION ${BINDIR} PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE WORLD_EXECUTE)
