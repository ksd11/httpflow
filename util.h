#ifndef util_h
#define util_h         /**防止重复定义/

#include <memory.h>
#include <cstring>
#include <cstdio>
#include <sstream>
#include <zlib.h>

struct packet_info {
    std::string src_addr;
    std::string dst_addr;
    bool        is_fin;
    std::string body;
};

extern bool is_atty;     /*全局变量*/

#define USE_ANSI_COLOR

#ifdef USE_ANSI_COLOR
#define ANSI_COLOR_RED     (is_atty ? "\x1b[31m" : "")
#define ANSI_COLOR_GREEN   (is_atty ? "\x1b[32m" : "")
#define ANSI_COLOR_YELLOW  (is_atty ? "\x1b[33m" : "")
#define ANSI_COLOR_BLUE    (is_atty ? "\x1b[34m" : "")
#define ANSI_COLOR_MAGENTA (is_atty ? "\x1b[35m" : "")          /*品红色*/
#define ANSI_COLOR_CYAN    (is_atty ? "\x1b[36m" : "")          /*青色*/
#define ANSI_COLOR_RESET   (is_atty ? "\x1b[0m"  : "")
#else
#define ANSI_COLOR_RED     ""
#define ANSI_COLOR_GREEN   ""
#define ANSI_COLOR_YELLOW  ""
#define ANSI_COLOR_BLUE    ""
#define ANSI_COLOR_MAGENTA ""
#define ANSI_COLOR_CYAN    ""
#define ANSI_COLOR_RESET   ""
#endif  // USE_ANSI_COLOR
/*声明一些的函数*/
bool is_plain_text(const std::string &s);

void get_join_addr(const std::string &src_addr, const std::string &dst_addr, std::string &ret);

std::string timeval2tr(const struct timeval *ts);

bool gzip_decompress(std::string &src, std::string &dst);

std::string urlencode(const std::string &s);

#endif
