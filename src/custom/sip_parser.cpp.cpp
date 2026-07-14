// Copyright (c) 2024 The idump project authors. SPDX-License-Identifier: MIT.
// This file is part of idump(https://github.com/wichue/idump).

#include "sip_parser.h"
#include <sstream>
#include <iostream>
#include <algorithm>
#include <cctype>
#include "Logger.h"

std::unordered_map<std::string, StatusCode> SipMessage::UserAgent_Status;
std::unordered_map<std::string, UeInfo> SipMessage::CallId_UserAgent;
static std::string trim(const std::string& str) {
    size_t start = str.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = str.find_last_not_of(" \t\r\n");
    return str.substr(start, end - start + 1);
}

static bool iequals(const std::string& a, const std::string& b) {
    if (a.length() != b.length()) return false;
    for (size_t i = 0; i < a.length(); ++i) {
        if (std::tolower(a[i]) != std::tolower(b[i])) return false;
    }
    return true;
}

bool SipMessage::parse(const std::string& raw) {
    isResponse = false;
    requestLine.clear();
    method.clear();
    requestUri.clear();
    sipVersion.clear();
    statusLine.clear();
    statusCode = 0;
    reasonPhrase.clear();
    headers.clear();
    body.clear();

    std::istringstream stream(raw);
    std::string line;

    if (!std::getline(stream, line)) return false;
    line = trim(line);

    // 区分请求还是响应：响应以 "SIP/2.0" 开头
    if (line.find("SIP/2.0") == 0) {
        isResponse = true;
        statusLine = line;

        std::istringstream ls(line);
        std::string ver;
        ls >> ver >> statusCode;
        std::getline(ls, reasonPhrase);
        reasonPhrase = trim(reasonPhrase);
        sipVersion = ver;
    } else {
        isResponse = false;
        requestLine = line;

        size_t pos1 = line.find(' ');
        if (pos1 != std::string::npos) {
            method = line.substr(0, pos1);
            size_t pos2 = line.find(' ', pos1 + 1);
            if (pos2 != std::string::npos) {
                requestUri = line.substr(pos1 + 1, pos2 - pos1 - 1);
                sipVersion = line.substr(pos2 + 1);
            } else {
                requestUri = line.substr(pos1 + 1);
            }
        }
    }

    // 头字段
    while (std::getline(stream, line)) {
        line = trim(line);
        if (line.empty()) break;

        size_t colon = line.find(':');
        if (colon == std::string::npos) continue;

        std::string name = line.substr(0, colon);
        std::string value = line.substr(colon + 1);
        name = trim(name);
        value = trim(value);

        if (!name.empty()) {
            headers[name].push_back(value);
        }
    }

    // 头字段解析完后，根据 Content-Length 读取消息体
    std::string contentLength = getHeader("Content-Length");
    if (!contentLength.empty()) {
        int len = std::stoi(contentLength);
        if (len > 0) {
            // 读取剩余内容作为 body，只取前 len 个字符
            std::string remaining;
            while (std::getline(stream, line)) {
                if (!remaining.empty()) remaining += "\n";
                remaining += line;
            }
            body = remaining.substr(0, len);
        } else {
            body.clear();
        }
    } else {
        // 没有 Content-Length 头，尝试读取剩余内容
        std::string remaining;
        while (std::getline(stream, line)) {
            if (!remaining.empty()) remaining += "\n";
            remaining += line;
        }
        body = remaining;
        // 如果 body 全是空白，清空
        if (body.find_first_not_of(" \t\r\n") == std::string::npos) {
            body.clear();
        }
    }
    return true;
}

std::string SipMessage::getHeader(const std::string& name) const {
    for (const auto& p : headers) {
        if (iequals(p.first, name)) {
            return p.second.empty() ? "" : p.second[0];
        }
    }
    return "";
}

std::vector<std::string> SipMessage::getHeaders(const std::string& name) const {
    for (const auto& p : headers) {
        if (iequals(p.first, name)) {
            return p.second;
        }
    }
    return {};
}

void SipMessage::print(uint32_t uIndex) const {
    std::cout << "-------start---------sip print uIndex:" << uIndex << std::endl;
    if (isResponse) {
        std::cout << "Status-Line: " << statusLine << std::endl;
        std::cout << "    Status-Code: " << statusCode << std::endl;
        std::cout << "    Reason-Phrase: " << reasonPhrase << std::endl;
    } else {
        std::cout << "Request-Line: " << requestLine << std::endl;
        std::cout << "    Method: " << method << std::endl;
        std::cout << "    Request-URI: " << requestUri << std::endl;
        std::cout << "    SIP-Version: " << sipVersion << std::endl;
    }

    std::cout << "Message Header:" << std::endl;
    for (const auto& p : headers) {
        for (const auto& v : p.second) {
            std::cout << "    " << p.first << ": " << v << std::endl;
        }
    }

    if (!body.empty()) {
        std::cout << "Message Body:" << std::endl;
        std::cout << body;

        if (body.find("active") != string::npos)
        {
            std::cout << "body uIndex:" << uIndex << ", active" << std::endl;
        }
        if (body.find("terminated") != string::npos)
        {
            std::cout << "body uIndex:" << uIndex  << "terminated" << std::endl;
        }
    }

    std::cout << "-------end---------sip print uIndex:" << uIndex << std::endl;
}

void SipMessage::match_ci_userAgent(int uIndex) {
    // 1.收到终端的请求，Method: SUBSCRIBE，Call-ID和User-Agent存储到哈希表
    if(!isResponse)
    {
        if(method=="SUBSCRIBE")
        {
            string ci = getHeader("Call-ID");
            if(!ci.empty())
            {
                string User_Agent = getHeader("User-Agent");
                UeInfo info;
                info.UserAgent = User_Agent;
                CallId_UserAgent[ci] = info;
            }
        }
    }

    // 2.把来自scscf的NOTIFY请求转发给终端，且是注册成功的NOTIFY，CSeq记录到哈希表
    if(!isResponse)
    {
        if(method=="NOTIFY")
        {
            if (body.find("active") != string::npos)
            {
                string ci = getHeader("Call-ID");
                if(!ci.empty())
                {
                    // 使用Call-ID查找 UserAgent
                    auto it = CallId_UserAgent.find(ci);
                    if (it != CallId_UserAgent.end())
                    {
                        it->second.CSeq = getHeader("CSeq");
                    }
                }
            }
        }
    }

    // 3.收到终端的NOTIFY响应
    if(isResponse) 
    {
        string CSep = getHeader("CSeq");
        // NOTIFY
        if (CSep.find("NOTIFY") == string::npos)
        {
            return;
        }

        string ci = getHeader("Call-ID");
        if(!ci.empty())
        {
            // 使用Call-ID查找 UserAgent
            auto it = CallId_UserAgent.find(ci);
            if (it != CallId_UserAgent.end())
            {
                // 当前报文CSep和第2步记录的CSep相同
                if(CSep == it->second.CSeq)
                {
                    // 使用UserAgent查找状态，记录状态
                    auto it2 = UserAgent_Status.find(it->second.UserAgent);
                    if (it2 != UserAgent_Status.end())
                    {
                        switch(statusCode) {
                            case 200:
                            it2->second.code_200++;
                            break;
                            case 481:
                            it2->second.code_481++;
                            break;
                            default:
                            it2->second.code_other++;
                        }
                        it2->second.number.push_back(uIndex);
                    }
                    else
                    {
                        StatusCode code = StatusCode{0,0,0};
                            switch(statusCode) {
                            case 200:
                            code.code_200++;
                            break;
                            case 481:
                            code.code_481++;
                            break;
                            default:
                            code.code_other++;
                        }
                        code.number.push_back(uIndex);
                        UserAgent_Status[it->second.UserAgent] = code;
                    }
                }
            }
        }
    }

}

string vec_to_str(const vector<int>& number)
{
    string res;
    for (size_t i = 0; i < number.size(); ++i)
    {
        if (i > 0)
        {
            res += "|";
        }
        res += to_string(number[i]);
    }
    return res;
}

void SipMessage::printAgentStat()
{
    std::cout << "match result:" << std::endl;
    for (auto &item : UserAgent_Status)
    {
        std::cout << "[User-Agent]: " << item.first << ", [200]:" << item.second.code_200 << ", [481]:" << item.second.code_481 << ", [other]:" << item.second.code_other 
        << ", [uIndex]:" << vec_to_str(item.second.number)
        << std::endl;
    }
}