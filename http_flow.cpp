#include <stdio.h>
#include <pcap.h>
#include <pcre.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <getopt.h>
#include <errno.h>
#include <string>
#include <sstream>
#include <list>
#include <map>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "util.h"
#include "custom_parser.h"
#include "data_link.h"
/*C++已经有一些编写好的头文件（比如标准函数库等等），他们存放在VC++的Include文件夹里。
当我们使用#include<文件名>命令时，编译器就到这个文件夹里去找对应的文件。
相反的，#include “文件名”命令则是先在当前文件所在的目录搜索是否有符合的文件，如果没有再到Include文件夹里去找相应的文件。
因此，无论这个文件是C++提供的还是自己编写的，使用#include “文件名”命令一定是正确的。*/
#define HTTPFLOW_VERSION "0.0.5"

#define MAXIMUM_SNAPLEN 262144      /*从每个报文中截取snaplen字节的数据，最大截取长度为262144*/

struct capture_config {
#define IFNAMSIZ    16
    int snaplen;                   /*从每个报文中截取snaplen字节的数据*/
    std::string output_path;       /*std输入输出标准,输出数据路径*/
    char device[IFNAMSIZ];
    std::string file_name;
    std::string filter;
    pcre* url_filter_re;
    pcre_extra* url_filter_extra;
    int datalink_size;
};

std::map<std::string, std::list<custom_parser *> > http_requests; // 所有请求pair作为键
/*http://blog.csdn.net/a19881029/article/details/38091243/*/
/**定义一个完整TCP数据报首部的结构体 http://blog.chinaunix.net/uid-26413668-id-3408115.html**/
struct tcphdr {
    uint16_t th_sport;       /* source port 来源端口*/
    uint16_t th_dport;       /* destination port TCP目的端口*/
    uint32_t th_seq;         /* sequence number TCP序列号（Sequence Number）*/
    uint32_t th_ack;         /* acknowledgement number 确认号（Acknowledgment Number）*/
#define TH_OFF(th)  (((th)->th_offx2 & 0xf0) >> 4)
    uint8_t th_offx2;       /* data offset数据偏移（Data Offset）4比特, rsvd 保留字段（Reserved） 占6比特*/
/* TCP flags
基于标记的TCP包匹配经常被用于过滤试图打开新连接的TCP数据包
TCP标记和他们的意义如下所列：

* F : FIN - 结束; 结束会话
* S : SYN - 同步; 表示开始会话请求
* R : RST - 复位;中断一个连接
* P : PUSH - 推送; 数据包立即发送
* A : ACK - 应答
* U : URG - 紧急
* E : ECE - 显式拥塞提醒回应
* W : CWR - 拥塞窗口减少
http://blog.csdn.net/hunanchenxingyu/article/details/26577201
 */
#define TH_FIN     0x01
#define TH_SYN     0x02
#define TH_RST     0x04
#define TH_PUSH    0x08
#define TH_ACK     0x10
#define TH_URG     0x20
#define TH_ECNECHO 0x40 /* ECN Echo */
#define TH_CWR     0x80 /* ECN Cwnd Reduced */
    uint8_t th_flags;
    uint16_t th_win;         /* window 滑动窗口（Window） 占2字节*/
    uint16_t th_sum;         /* checksumTCP校验和(Checksum)  占2字节 */
    uint16_t th_urp;         /* urgent pointer 紧急指针(Urgent Pointer)  占2字节*/
};
/**处理TCP**/
static bool process_tcp(struct packet_info *packet, const u_char *content, size_t len) {
    if (len < sizeof(struct tcphdr)) {
        std::cerr << "received truncated TCP datagram." << std::endl;
        return false;
    }
	/**reinterpret_cast是C++里的强制类型转换符。**/
    const struct tcphdr *tcp_header = reinterpret_cast<const struct tcphdr *>(content);

    size_t tcp_header_len = TH_OFF(tcp_header) << 2;
    if (len < tcp_header_len) {
        std::cerr << "received truncated TCP datagram." << std::endl;
        return false;
    }
	/**ntohs()是一个函数名，作用是将一个16位数由网络字节顺序转换为主机字节顺序**/
    uint16_t src_port = ntohs(tcp_header->th_sport);
    uint16_t dst_port = ntohs(tcp_header->th_dport);

    char buff[128];
    std::snprintf(buff, 128, "%s:%d", packet->src_addr.c_str(), src_port);
    packet->src_addr.assign(buff);
    std::snprintf(buff, 128, "%s:%d", packet->dst_addr.c_str(), dst_port);
	/**assign()  C++ string类的成员函数，用于赋值操作。**/
    packet->dst_addr.assign(buff);
    packet->is_fin = !!(tcp_header->th_flags & (TH_FIN | TH_RST));

    content += tcp_header_len;
    packet->body = std::string(reinterpret_cast<const char *>(content), len - tcp_header_len);
    return true;
}
/**IP数据包格式,http://www.cnblogs.com/embedded-linux/p/4986449.html**/
/*
0 4 8 16 31

|4位版本 | 4位首部长度 | 8位服务类型 | 16位总长度（字节数）|

|16位标识 | 3位标志 | 13位片偏移 |

|8位生存时间| 8位协议 | 16位首部校验和 |

|32位源IP地址|

|32位目的IP地址|

|选项（可无）|

|数据|
*/
struct ip {
    uint8_t ip_vhl;     /* header length, version 4位首部长度（ip_hl)：这个值以4字节为单位，IP协议首部的固定长度为20个字节，如果IP包没有选项，那么这个值为5.*/
#define IP_V(ip)    (((ip)->ip_vhl & 0xf0) >> 4)/*4位版本（ip_v):这里是4，现在IPV6已经出来了。*/
#define IP_HL(ip)   ((ip)->ip_vhl & 0x0f)
    uint8_t ip_tos;     /* type of service ip_tos服务类型：说明提供的优先权*/
    uint16_t ip_len;     /* total length ip_len:IP数据包的总长度，最大为65535，字节数。包括IP首部和IP层payload（数据）。*/
    uint16_t ip_id;      /* identification ip_id:标识这个IP数据包*/
    uint16_t ip_off;     /* fragment offset field ip_off碎片偏移：和上面ID一起用来重组碎片*/
#define IP_DF 0x4000            /* dont fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
    uint8_t ip_ttl;     /* time to live p_ttl生存时间：每经过一个路由时减1，直到为0时被抛弃。单位不是秒，而是跳hop。*/
    uint8_t ip_p;       /* protocol ip_p协议：表示创建这个IP数据包的高层协议，如TCP，UDP，ICMP和IGMP协议。*/
    uint16_t ip_sum;     /* checksum ip_sum首部校验和：提供对首部数据的校验。*/
    uint32_t ip_src, ip_dst;  /* source and dest address ip_src,ip_dst:发送者和校验者IP地址*/
};
/**处理IPV4**/
/*检查是否是ipv4的数据包，如果是的话去掉ip头，返回tcp数据包*/
static bool process_ipv4(struct packet_info *packet, const u_char *content, size_t len) {
    if (len < sizeof(struct ip)) {
        std::cerr << "received truncated IP datagram." << std::endl;
        return false;
    }
    const struct ip *ip_header = reinterpret_cast<const struct ip *>(content);
    if (4 != IP_V(ip_header) || ip_header->ip_p != IPPROTO_TCP) {
        return false;
    }
    size_t ip_header_len = IP_HL(ip_header) << 2;
    size_t ip_len = ntohs(ip_header->ip_len);

    char src_addr[INET_ADDRSTRLEN];
    char dst_addr[INET_ADDRSTRLEN];
	/*inet_ntop这个函数转换网络二进制结构到ASCII类型的地址，参数的作用和inet_pton相同，
	只是多了一个参数socklen_t cnt,他是所指向缓存区dst的大小，避免溢出，
	如果缓存区太小无法存储地址的值，则返回一个空指针，并将errno置为ENOSPC。*/
    inet_ntop(AF_INET, &ip_header->ip_src, src_addr, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &ip_header->ip_dst, dst_addr, INET_ADDRSTRLEN);
    packet->src_addr.assign(src_addr);
    packet->dst_addr.assign(dst_addr);

    if (ip_len > len || ip_len < ip_header_len) {
        std::cerr << "received truncated IP datagram." << std::endl;
        return false;
    }
    size_t ip_payload_len = ip_len - ip_header_len;
    content += ip_header_len;
    return process_tcp(packet, content, ip_payload_len);
}

#define    ETHER_ADDR_LEN      6
#define    ETHERTYPE_IP        0x0800    /* IP protocol */
/**网络包ether_header    http://blog.csdn.net/guofu8241260/article/details/23248875
https://wenku.baidu.com/view/73f96d25a5e9856a561260cd.html
**/
struct ether_header {
    u_char ether_dhost[ETHER_ADDR_LEN];/**目的MAC地址**/
    u_char ether_shost[ETHER_ADDR_LEN];/**源MAC地址**/
    u_short ether_type;/**协议类型 **/
};
/**处理数据包**/
void process_packet(const pcre *url_filter_re, const pcre_extra *url_filter_extra, const std::string &output_path, const u_char* data, size_t len) {

    struct packet_info packet;
    bool ret = process_ipv4(&packet, data, len);
    if ((!ret || packet.body.empty()) && !packet.is_fin) {
        return;
    }

    std::string join_addr;
    get_join_addr(packet.src_addr, packet.dst_addr, join_addr);

    std::map<std::string, std::list<custom_parser *> >::iterator iter = http_requests.find(join_addr);
    if (iter == http_requests.end() || iter->second.empty()) {
        if (!packet.body.empty()) {
            custom_parser *parser = new custom_parser;
            if (parser->parse(packet.body, HTTP_REQUEST)) { // 重点！！解析包
                parser->set_addr(packet.src_addr, packet.dst_addr);
                std::list<custom_parser *> requests;
                requests.push_back(parser);
                http_requests.insert(std::make_pair(join_addr, requests));
            } else {
                delete parser;
            }
        }
    } else {
        std::list<custom_parser *> &parser_list = iter->second;
        custom_parser *last_parser = *(parser_list.rbegin()); // 获取最后一个packet

        if (!packet.body.empty()) {
            if (last_parser->is_request_address(packet.src_addr)) {
                // Request
                if (last_parser->is_request_complete()) {
                    custom_parser* parser = new custom_parser;
                    if (parser->parse(packet.body, HTTP_REQUEST)) {
                        parser->set_addr(packet.src_addr, packet.dst_addr);
                        parser_list.push_back(parser);
                    } else {
                        delete parser;
                    }
                } else {
                    last_parser->parse(packet.body, HTTP_REQUEST);
                }
            } else {
                for (std::list<custom_parser *>::iterator it = parser_list.begin(); it != parser_list.end(); ++it) {
                    if (!(*it)->is_response_complete()) {
                        (*it)->parse(packet.body, HTTP_RESPONSE);
                        break;
                    } else {
                        std::cerr << ANSI_COLOR_RED << "get response exception, body [" << packet.body
                                  << "]" << ANSI_COLOR_RESET << std::endl;
                    }
                }
            }
        }

        for (std::list<custom_parser *>::iterator it = parser_list.begin(); it != parser_list.end();) {
            if ((*it)->is_response_complete() || packet.is_fin) {
                (*it)->save_http_request(url_filter_re, url_filter_extra, output_path, join_addr);
                delete (*it);
                it = iter->second.erase(it);
            } else {
                ++it;
            }
        }

        if (iter->second.empty()) {
            http_requests.erase(iter);
        }
    }
}

void pcap_callback(u_char *arg, const struct pcap_pkthdr *header, const u_char *content) {

    // Data: |       Mac         |        Ip          |           TCP                  |
    // Len : |   ETHER_HDR_LEN   |   ip_header->ip_hl << 2   | tcp_header->th_off << 2 + sizeof body |

    capture_config *conf = reinterpret_cast<capture_config *>(arg);

    // skip datalink
    content += conf->datalink_size;
    size_t len = header->caplen - conf->datalink_size;

    return process_packet(conf->url_filter_re, conf->url_filter_extra, conf->output_path, content, len);
}

static const struct option longopts[] = {
        {"help",            no_argument,       NULL, 'h'},
        {"interface",       required_argument, NULL, 'i'},
        {"filter",          required_argument, NULL, 'f'},
        {"url_filter",      required_argument, NULL, 'u'},
        {"pcap-file",       required_argument, NULL, 'r'},
        {"snapshot-length", required_argument, NULL, 's'},
        {"output-path",     required_argument, NULL, 'w'},
        {NULL, 0,                              NULL, 0}
};

#define SHORTOPTS "hi:f:u:r:w:"

int print_usage() {
    std::cerr << "libpcap version " << pcap_lib_version() << "\n"
              << "httpflow version " HTTPFLOW_VERSION "\n"
              << "\n"
              << "Usage: httpflow [-i interface | -r pcap-file] [-f packet-filter] [-u url-filter] [-w output-path]" << "\n"
              << "\n"
              << "  -i interface      Listen on interface" << "\n"
              << "  -r pcap-file      Read packets from file (which was created by tcpdump with the -w option)" << "\n"
              << "                    Standard input is used if file is '-'" << "\n"
              << "  -f packet-filter  Selects which packets will be dumped" << "\n"
              << "                    If filter expression is given, only packets for which expression is 'true' will be dumped" << "\n"
              << "                    For the expression syntax, see pcap-filter(7)" << "\n"
              << "  -u url-filter     Matches which urls will be dumped" << "\n"
              << "  -w output-path    Write the http request and response to a specific directory" << "\n"
              << "\n"
              << "  For more information, see https://github.com/six-ddc/httpflow" << "\n\n";
    exit(0);
}
/*extern是计算机语言中的一个函数，可置于变量或者函数前，以表示变量或者函数的定义在别的文件中。
提示编译器遇到此变量或函数时，在其它模块中寻找其定义，另外，extern也可用来进行链接指定。*/
extern char *optarg;            /* getopt(3) external variables */
extern int optind, opterr, optopt;

capture_config *default_config() {
    capture_config *conf = new capture_config;

    conf->snaplen = MAXIMUM_SNAPLEN;
    conf->device[0] = 0;
    conf->filter = "tcp";
    conf->url_filter_re = NULL;
    conf->url_filter_extra = NULL;

    return conf;
}
/*
int argc, char **argv与键盘输入有关系
*/
int init_capture_config(int argc, char **argv, capture_config *conf, char *errbuf) {

    // pcap_if_t *devices = NULL, *iter = NULL;
    const char *default_device = NULL;
    int cnt, op, i;
    std::string url_regex;
	/*getopt_long支持长选项的命令行解析,
	返回值（3）几种常见返回值：
    (a)每次调用该函数，它都会分析一个选项，并且返回它的短选项，如果分析完毕，即已经没有选项了，则会返回-1。
    (b)如果getopt_long()在分析选项时，遇到一个没有定义过的选项，则返回值为‘?’，此时，程序员可以打印出所定义命令行的使用信息给用户。
    (c)当处理一个带参数的选项时，全局变量optarg会指向它的参数
    (d)当函数分析完所有参数时，全局变量optind（into argv）会指向第一个‘非选项’的位置*/
	/*getopt_long匹配print_usage，配置参数*/
    while ((op = getopt_long(argc, argv, SHORTOPTS, longopts, NULL)) != -1) {
        switch (op) {
            case 'i':
			/*strncpy函数从源字符串中复制指定个数的字符到目标字符串中，并返回目标字符串，
			如果指定字符数小于或等于源字符串的长度，空字符不会自动添加到被复制的字符串后面。
			如果指定字符数大于源字符串的长度，目标字符串将被空字符补足到指定的长度。
			如果源字符串和目标字符串存在叠加的情况（即两个字符串都是同字符串的一部分，且有部分内容首尾重合），则strncpy的运行结果是不确定的。
			拷贝函数*/
                std::strncpy(conf->device, optarg, sizeof(conf->device));
                break;
            case 'f':
                conf->filter = optarg;
                break;
            case 'u':
                url_regex.assign(optarg);
                const char *err;
                int erroffset;
                conf->url_filter_re = pcre_compile(url_regex.c_str(), 0, &err, &erroffset, NULL);
                if (!conf->url_filter_re) {
                    std::cerr << "invalid regular expression at offset " << erroffset << ": " << err << std::endl;
                    exit(1);
                }
                conf->url_filter_extra = pcre_study(conf->url_filter_re, 0, &err);
                break;
            case 'r':
                conf->file_name = optarg;
                break;
            case 'h':
                print_usage();
                break;
            case 'w':
                conf->output_path = optarg;
                break;
            default:
                exit(1);
                break;
        }
    }

    if (conf->device[0] == 0) {
        default_device = pcap_lookupdev(errbuf);
        if (default_device) {
            std::strncpy(conf->device, default_device, sizeof(conf->device));
        }
    }

    if (!conf->output_path.empty()) {
        int mk_ret = mkdir(conf->output_path.c_str(), ACCESSPERMS);
        if (mk_ret != 0 && errno != EEXIST) {
            std::cerr << "mkdir [" << conf->output_path << "] failed. ret=" << mk_ret << std::endl;
            exit(1);
        }
    }

    if (conf->file_name.empty()) {
        std::cerr << "interface: " << conf->device << std::endl;
    } else {
        if (conf->file_name == "-") {
            std::cerr << "pcap-file: [stdin]" << std::endl;
        } else {
            std::cerr << "pcap-file: " << conf->file_name << std::endl;
        }
    }
    if (!conf->output_path.empty()) {
        std::cerr << "output_path: " << conf->output_path << std::endl;
    }
    std::cerr << "filter: " << conf->filter << std::endl;
    if (!url_regex.empty()) {
        std::cerr << "url_filter: " << url_regex << std::endl;
    }

    return 0;
}
/*
argc是命令行总的参数个数  
argv[]是argc个参数，其中第0个参数是程序的全名，以后的参数  
argc记录了用户在运行程序的命令行中输入的参数的个数。  
arg[]指向的数组中至少有一个字符指针，即arg[0].他通常指向程序中的可执行文件的文件名。在有些版本的编译器中还包括程序
文件所在的路径。
*/
int main(int argc, char **argv) {
	/*fileno()用来取得参数stream指定的文件流所使用的文件描述符,返回值：某个数据流的文件描述符*/
	/*isatty，函数名。主要功能是检查设备类型 ， 判断文件描述词是否是为终端机。返回值：如果参数desc所代表的文件描述词为一终端机则返回1，否则返回0。*/
	/*stdout, stdin, stderr的中文名字分别是标准输出，标准输入和标准错误。大多数环境中，stdin指向键盘，stdout、stderr指向显示器,
	eg:
	fprintf(stdout,"hello world!\n");
	屏幕上将打印出"helloworld!"来。
	同样，我们使用：fread(ptr,1,10,stdin);
	上面的代码会接收用户输入在终端里的字符，并存在ptr中*/
	/*判断输出终端是否好使*/
    is_atty = isatty(fileno(stdout));
	/*定义一个长度为PCAP_ERRBUF_SIZE的errbuf数组，PCAP_ERRBUF_SIZE这个值在errno.h定义*/
    char errbuf[PCAP_ERRBUF_SIZE];
	/*pcap_t是在pcap.h中定义的网络接口对象，实例化一个pcap_t网络接口对象句柄*/
    pcap_t *handle = NULL;
	/*定义网络设备的网络号和掩码。net参数和mask参数都是bpf_u_int32指针*/
    bpf_u_int32 net, mask;
	/*bpf_program这个结构体是干啥的？？？？*/
    struct bpf_program fcode;
    int datalink_id;
	/*其中std是名称空间，防止重复。比如说许多人给函数取名可能都叫f1（）；你使用的时候就可能造成问题。如果各人均把自己的f1（）放进自己的名称空间，我们在使用的时候带上名称空间就不会有问题*/
    std::string datalink_str;
	/*实例化结构体capture_config，cap_conf为指针地址*/
    capture_config *cap_conf = default_config();
    if (-1 == init_capture_config(argc, argv, cap_conf, errbuf)) {
        return 1;
    }

    if (!cap_conf->file_name.empty()) {
		/*打开以前保存捕获数据包的文件，用于读取。fname参数指定打开的文件名。
		该文件中的数据格式与tcpdump和tcpslice兼容。"-"为标准输入。
		errbuf参数则仅在pcap_open_offline()函数出错返回NULL时用于传递错误消息。*/
		
        handle = pcap_open_offline(cap_conf->file_name.c_str(), errbuf);
        if (!handle) {
            std::cerr << "pcap_open_offline(): " << errbuf << std::endl;
            return 1;
        }
    } else {
		/*
		http://blog.sina.com.cn/s/blog_679b384601012rat.html
		描述：该函数用于监测网卡所在网络的网络地址和子网掩码。
		参数：
		char *devic:网卡的描述符指针，由pcap_looupdev函数获取；
		bpf_u_int32 *netp:存放网络地址；
		bpf_u_int32 *maskp：存放子网掩码；
		char * errbuf: 存放出错信息；
		返回值：如果函数执行成功，则返回值为0,否则返回值为-1,并在errbuf中存放出错信息。
		*/
        if (-1 == pcap_lookupnet(cap_conf->device, &net, &mask, errbuf)) {
            std::cerr << "pcap_lookupnet(): " << errbuf << std::endl;
            return 1;
        }
		/*
		获得用于捕获网络数据包的数据包捕获描述字。
		device参数为指定打开的网络设备名。
		snaplen参数定义捕获数据的最大字节数。
		promisc指定是否将网络接口置于混杂模式。
		to_ms参数指定超时时间（毫秒）。
		ebuf参数则仅在pcap_open_live()函数出错返回NULL时用于传递错误消息。
		*/
        handle = pcap_open_live(cap_conf->device, cap_conf->snaplen, 0, 1000, errbuf);
        if (!handle) {
            std::cerr << "pcap_open_live(): " << errbuf << std::endl;
            return 1;
        }
		/*返回数据链路层类型，例如DLT_EN10MB。*/
        pcap_datalink(handle);
    }
	/*
	描述：该函数用于将str指定的规则整合到fp过滤程序中去，并生成过滤程序入口地址，用于过滤选择期望的数据报；
    参数：
    pcap_t *p：pcap_open_live返回的数据报捕获的指针；
    struct bpf_program *fp:指向一个子函数用于过滤，在pcap_compile()函数中被赋值；
    char *str:该字符串规定过滤规则；
    int optimize:规定了在结果代码上的选择是否被执行；
    bpf_u_int32 netmask:该网卡的子网掩码，可以通过pcap_lookupnet()获取；
    返回值：
    如果成功执行，返回0,否则返回-1；
	*/
    if (-1 == pcap_compile(handle, &fcode, cap_conf->filter.c_str(), 0, mask)) {
        std::cerr << "pcap_compile(): " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        return 1;
    }
	/*
	指定一个过滤程序。fp参数是bpf_program结构指针，通常取自
	pcap_compile()函数调用。出错时返回-1；成功时返回0。
	*/
    if (-1 == pcap_setfilter(handle, &fcode)) {
        std::cerr << "pcap_setfilter(): " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        return 1;
    }

    pcap_freecode(&fcode);
	/*返回数据链路层类型,DLT_EN10MB*/
	datalink_id = pcap_datalink(handle);
	datalink_str = datalink2str(datalink_id);
	/*返回数据链路层类型长度，例如DLT_EN10MB的长度为14。*/
	cap_conf->datalink_size = datalink2off(datalink_id);
    std::cerr << "datalink: " << datalink_id << "(" << datalink_str << ") header size: " << cap_conf->datalink_size << std::endl;
	/*功能基本与pcap_dispatch()函数相同，
	只不过此函数在cnt个数据包被处理或出现错误时才返回，但读取超时不会返回。
	而如果为pcap_open_live()函数指定了一个非零值的超时设置，然后调用pcap_dispatch()函数，
	则当超时发生时pcap_dispatch()函数会返回。
	cnt参数为负值时pcap_loop()函数将始终循环运行，除非出现错误。
	*/
    if (-1 == pcap_loop(handle, -1, pcap_callback, reinterpret_cast<u_char *>(cap_conf))) {
        std::cerr << "pcap_loop(): " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        return 1;
    }

    delete cap_conf;

    pcap_close(handle);
    return 0;
}
