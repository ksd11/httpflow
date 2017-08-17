#include "util.h"

bool is_atty = true;
/*定义一些函数*/
bool is_plain_text(const std::string &s) {
	//判断读入字符串是否是纯文本文件
	// The algorithm works by dividing the set of bytecodes [0..255] into three
	// categories:
	// 	- The white list of textual bytecodes://白名单
	//  	9 (TAB), 10 (LF), 13 (CR), 32 (SPACE) to 255.
	// 	- The gray list of tolerated bytecodes://灰名单
	//  	7 (BEL), 8 (BS), 11 (VT), 12 (FF), 26 (SUB), 27 (ESC).
	// 	- The black list of undesired, non-textual bytecodes://黑名单
	//  	0 (NUL) to 6, 14 to 31.
	// If a file contains at least one byte that belongs to the white list and
	// no byte that belongs to the black list, then the file is categorized as
	// plain text; otherwise, it is categorized as binary.  (The boundary case,
	// when the file is empty, automatically falls into the latter category.)
    if (s.empty()) {
        return true;
    }//空的内容为纯文本文件
    size_t white_list_char_count = 0;//白名单字符个数
	for (int i = 0; i < s.size(); ++i) {
		const unsigned char c = s[i];   //字符串引用取字符值
        if (c == 9 || c == 10 || c == 13 || (c >= 32 && c <= 255)) {
            // white list
            white_list_char_count++;
        } else if ((c <= 6) || (c >= 14 && c <= 31)) {
            // black list
            return 0;//return false
        }
	}
    return white_list_char_count >= 1 ? true : false;  //secondary condition as binary
}
/*src_addr源地址，dst_addr目的地址，调整后的字符串*/
void get_join_addr(const std::string &src_addr, const std::string &dst_addr, std::string &ret) {
    if (src_addr < dst_addr) {
        ret = src_addr + "-" + dst_addr;
    } else {
        ret = dst_addr + "-" + src_addr;
    }
}
//结构指针
/*
直接存储年月日的是一个结构：
struct tm
{
    int tm_sec;  //秒，正常范围0-59， 但允许至61
    int tm_min;  //分钟，0-59
    int tm_hour; //小时， 0-23
    int tm_mday; //日，即一个月中的第几天，1-31
    int tm_mon;  //月， 从一月算起，0-11  1+p->tm_mon;
    int tm_year;  //年， 从1900至今已经多少年  1900＋ p->tm_year;
    int tm_wday; //星期，一周中的第几天， 从星期日算起，0-6
    int tm_yday; //从今年1月1日到目前的天数，范围0-365
    int tm_isdst; //日光节约时间的旗标
};
需要特别注意的是，年份是从1900年起至今多少年，而不是直接存储如2011年，月份从0开始的，0表示一月，星期也是从0开始的， 0表示星期日，1表示星期一。
*/
std::string timeval2tr(const struct timeval *ts) {
    struct tm *local_tm = localtime(&ts->tv_sec);
    std::string time_str;
    time_str.resize(15);//resize调整容器中有效数据区域的尺寸，如果尺寸变小，原来数据多余的截掉。若尺寸变大，不够的数据用该函数的第二个参数填充，影响size
    sprintf(&time_str[0], "%02d:%02d:%02d.%06d", local_tm->tm_hour, local_tm->tm_min, local_tm->tm_sec, (int)ts->tv_usec);//打印出系统时间，精确到微秒
    return time_str;
}

#define GZIP_CHUNK 16384      //块传输编码

bool gzip_decompress(std::string &src, std::string &dst) {
    z_stream zs;      //zstream (avoids casting and memory allocation) 
    memset(&zs, 0, sizeof(zs));//在一段内存中填充某个给定的值，它对较大的结构体或数组进行清零操作的一种最快方法。

    // gzip
	//只有设置为MAX_WBITS + 16才能在解压带header和trailer的文本
    if (inflateInit2(&zs, 16 + MAX_WBITS) != Z_OK) {
        return false;
    }
    //强转,typedef Byte FAR Bytef,二进制
    zs.next_in = reinterpret_cast<Bytef *>(&src[0]);
    zs.avail_in = src.size();//源字串的大小

    int ret;
    char outbuffer[GZIP_CHUNK];

    do {
        zs.next_out = reinterpret_cast<Bytef *>(outbuffer);
        zs.avail_out = sizeof(outbuffer);//字节大小
        ret = inflate(&zs, 0);//解压缩文件
        if (dst.size() < zs.total_out) {
            dst.append(outbuffer, zs.total_out - dst.size());
        }
    } while (ret == Z_OK);
    inflateEnd(&zs);
    return ret == Z_STREAM_END;// Z_STREAM_END 表示解压缩完成,并且校验和匹配
}
//url编码
std::string urlencode(const std::string &s) {
    static const char lookup[] = "0123456789abcdef";
    std::stringstream e;
    for (int i = 0; i < s.size(); ++i) {
        const char c = s[i];
        if (('0' <= c && c <= '9') || ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') ||
            (c == '-' || c == '_' || c == '.' || c == '~')) {
            e << c;
        } else {
            e << '%';
			//十进制转换为十六进制
            e << lookup[(c & 0xF0) >> 4];//与运算，右移四位，左边补0,对16取整
            e << lookup[(c & 0x0F)];//对16求余
        }
    }
    return e.str();
}
