// Copyright (c) 2024 The idump project authors. SPDX-License-Identifier: MIT.
// This file is part of idump(https://github.com/wichue/idump).

#ifndef SIP_PARSER_H
#define SIP_PARSER_H

#include <string>
#include <map>
#include <vector>
#include <unordered_map>
#include <stdint.h>

using namespace std;
struct StatusCode{
    int code_200;
    int code_481;
    int code_other;
    vector<int> number;
};

struct UeInfo{
    string UserAgent;
    string CSeq;
};

class SipMessage {
public:
    // 类型标识
    bool isResponse = false;

    // 请求行（请求消息）
    std::string requestLine;    // 完整请求行
    std::string method;         // REGISTER, SUBSCRIBE 等
    std::string requestUri;     // Request-URI
    std::string sipVersion;     // SIP/2.0

    // 状态行（响应消息）
    std::string statusLine;     // 完整状态行
    int statusCode = 0;
    std::string reasonPhrase;

    // 头字段
    std::map<std::string, std::vector<std::string>> headers;

    // 消息体
    std::string body;

    bool parse(const std::string& raw);
    std::string getHeader(const std::string& name) const;
    std::vector<std::string> getHeaders(const std::string& name) const;
    void print(uint32_t uIndex) const;
    static void printAgentStat();

    void match_ci_userAgent(int uIndex);

private:
    static std::unordered_map<string,UeInfo> CallId_UserAgent;
    static std::unordered_map<string,StatusCode> UserAgent_Status;
};

#endif