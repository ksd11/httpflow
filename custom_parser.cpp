#include "custom_parser.h"
#include "util.h"
#include <sys/stat.h>

/*报文初始化*/
custom_parser::custom_parser() {
    request_complete_flag = false;
    response_complete_flag = false;
    gzip_flag = false;
    http_parser_init(&parser, HTTP_REQUEST);
    parser.data = this;
    // 初始化setting，当解析http packet某个阶段的时候会被调用 -- 钩子函数！
    http_parser_settings_init(&settings);
    settings.on_url = on_url;
    settings.on_header_field = on_header_field;
    settings.on_header_value = on_header_value;
    settings.on_headers_complete = on_headers_complete;
    settings.on_body = on_body;
    settings.on_message_complete = on_message_complete;
}
//区分完request和response，执行http解析
bool custom_parser::parse(const std::string &body, enum http_parser_type type) {
    if (parser.type != type) {
        http_parser_init(&parser, type); // 默认初始化为一个request，如果是response，需要重新初始化
    }
    if (parser.type == HTTP_REQUEST) {
        request.append(body);
    } else if (parser.type == HTTP_RESPONSE) {
        response.append(body);
    }
    size_t parse_bytes = http_parser_execute(&parser, &settings, body.c_str(), body.size());
    return parse_bytes > 0 && HTTP_PARSER_ERRNO(&parser) == HPE_OK;
}

std::string custom_parser::get_response_body() const {
    return response_body;
}
//请求地址，相应地址
void custom_parser::set_addr(const std::string &src_addr, const std::string &dst_addr) {
    this->request_address = src_addr;
    this->response_address = dst_addr;
}

//从data里面取对应的url和method
int custom_parser::on_url(http_parser *parser, const char *at, size_t length) {
    custom_parser *self = reinterpret_cast<custom_parser *>(parser->data);
    self->url.assign(at, length);
    self->method.assign(http_method_str(static_cast<enum http_method>(parser->method)));
    return 0;
};
//取头域
int custom_parser::on_header_field(http_parser *parser, const char *at, size_t length) {
    custom_parser *self = reinterpret_cast<custom_parser *>(parser->data);
    self->temp_header_field.assign(at, length);
    for (size_t i = 0; i < length; ++i) {
        if (at[i] >= 'A' && at[i] <= 'Z') {
            self->temp_header_field[i] = at[i] ^ (char) 0x20; // 大写转化为小写
        }
    }
    return 0;
}
//头域值 当读取到一个header和其value是回调
int custom_parser::on_header_value(http_parser *parser, const char *at, size_t length) {
    custom_parser *self = reinterpret_cast<custom_parser *>(parser->data);
    if (parser->type == HTTP_RESPONSE) {
        if (self->temp_header_field == "content-encoding" && std::strstr(at, "gzip")) {
            self->gzip_flag = true;
        }
    } else {
        if (self->temp_header_field == "host") { // 如果读取到的是host的value
            self->host.assign(at, length);
        }
    }
    // std::cout << self->temp_header_field <<  ":" << std::string(at, length) << std::endl;
    return 0;
}
// 头部字段读取完毕时回调
int custom_parser::on_headers_complete(http_parser *parser) {
    custom_parser *self = reinterpret_cast<custom_parser *>(parser->data);
    if (parser->type == HTTP_REQUEST) {
        self->request_header = self->request.substr(0, parser->nread);
    } else if (parser->type == HTTP_RESPONSE) {
        self->response_header = self->response.substr(0, parser->nread);
    }
    return 0;
}
//消息体
int custom_parser::on_body(http_parser *parser, const char *at, size_t length) {
    custom_parser *self = reinterpret_cast<custom_parser *>(parser->data);
    // std::cout << __func__ << " " << self->url << std::endl;
    if (parser->type == HTTP_REQUEST) {
        self->request_body.append(at, length);
    } else if (parser->type == HTTP_RESPONSE) {
        self->response_body.append(at, length);
    }
    return 0;
}

int custom_parser::on_message_complete(http_parser *parser) {
    custom_parser *self = reinterpret_cast<custom_parser *>(parser->data);
    if (parser->type == HTTP_REQUEST) {
        self->request_complete_flag = true;
    } else if (parser->type == HTTP_RESPONSE) {
        self->response_complete_flag = true;
    }
    if (self->gzip_flag) {
        std::string new_body;
        if (gzip_decompress(self->response_body, new_body)) {
            self->response_body = new_body;
        } else {
            std::cerr << ANSI_COLOR_RED << "[decompress error]" << ANSI_COLOR_RESET << std::endl;
        }
    }
    return 0;
}
// 使用lipcre库来过滤
bool custom_parser::filter_url(const pcre *url_filter_re, const pcre_extra *url_filter_extra, const std::string &url) {
    if (!url_filter_re) return true;
    int ovector[30];
    int rc = pcre_exec(url_filter_re, url_filter_extra, url.c_str(), url.size(), 0, 0, ovector, 30);
    return rc >= 0;
}

#include <stdio.h>
#include <string.h>
#include <unistd.h>

/*******************************************************************
** 函数名:     folder_mkdirs
** 函数描述:   可多级建立文件夹
** 参数:       folder_path:目标文件夹路径
** 返回:       1 - 目标文件夹存在，2 - 创建失败
********************************************************************/
static int folder_mkdirs(const char *folder_path)
{	
	if(!access(folder_path, F_OK)){                        /* 判断目标文件夹是否存在 */
		return 0;
	}

	char path[256];                                        /* 目标文件夹路径 */
	char *path_buf;                                        /* 目标文件夹路径指针 */
	char temp_path[256];                                   /* 存放临时文件夹路径 */
	char *temp;                                            /* 单级文件夹名称 */
	int temp_len;                                          /* 单级文件夹名称长度 */
	
	memset(path, 0, sizeof(path));
	memset(temp_path, 0, sizeof(temp_path));
	strcat(path, folder_path);
	path_buf = path;
    if(*folder_path == '/'){
        strcat(temp_path, "/");
    }

	while((temp = strsep(&path_buf, "/")) != NULL){        /* 拆分路径 */
		temp_len = strlen(temp);	
		if(0 == temp_len){
			continue;
		}
		strcat(temp_path, temp);
        strcat(temp_path, "/");
		// printf("temp_path = %s\n", temp_path);
		if(-1 == access(temp_path, F_OK)){                 /* 不存在则创建 */
			if(-1 == mkdir(temp_path, 0777)){
				return -1;
			}
		}
	}
	return 0;
}


static void mkdir_helper(std::string save_dirname){
    // int mk_ret = mkdir(save_dirname.c_str(), ACCESSPERMS);
    int mk_ret = folder_mkdirs(save_dirname.c_str());
    if (mk_ret != 0 && errno != EEXIST) {
        std::cerr << "mkdir [" << save_dirname << "] failed. ret=" << mk_ret << std::endl;
        exit(1);
    }
}


std::string custom_parser::get_resonable_filename(std::string save_dirname){
    std::cout << save_dirname << std::endl;
    std::cout << this->url << std::endl;

    if(this->url[this->url.length() - 1] == '/'){
        mkdir_helper(save_dirname + this->url);
        return this->url + "index.html";
    }
    int slash_p = this->url.rfind('/');
    int dot_p = this->url.rfind('.');
    if(slash_p != -1 && slash_p < dot_p){
        std::cout << slash_p << " "<< dot_p << std::endl;
        mkdir_helper(save_dirname + "/" + this->url.substr(0, slash_p));
        return this->url ;
    }

    mkdir_helper(save_dirname + "/" + this->url);
    return this->url + "/index.html";
    // return this->url ;
}

// 如果存在output_path，则输出到output，否则，打印到标准输出
void custom_parser::save_http_request(const pcre *url_filter_re, const pcre_extra *url_filter_extra, const std::string &output_path, const std::string &join_addr) {
    std::string host_with_url = host + url;
    if (!filter_url(url_filter_re, url_filter_extra, host_with_url)) {
        return;
    }
    std::cout << ANSI_COLOR_CYAN << request_address << " -> " << response_address << " " << host_with_url << ANSI_COLOR_RESET << std::endl;
    if (!output_path.empty()) {

        // 文件保存在 output_path/host/目录下
        std::string save_dirname = output_path + "/" + host;
        mkdir_helper(save_dirname);

        std::string save_filename = save_dirname + "/" + get_resonable_filename(save_dirname);
        std::ofstream out(save_filename.c_str(), std::ios::trunc | std::ios::out);
        if (out.is_open()) {
            out << *this << std::endl;
            out.close();
        } else {
            std::cerr << "ofstream [" << save_filename << "] is not opened." << std::endl;
            out.close();
            exit(1);
        }
    } else {
        std::cout << *this << std::endl;
    }
}

std::ostream& operator<<(std::ostream& out, const custom_parser& parser) {
    out
        << ANSI_COLOR_GREEN
        << parser.request_header
        << ANSI_COLOR_RESET;
    if (!is_atty || is_plain_text(parser.request_body)) {
        out << parser.request_body;
    } else {
        out << ANSI_COLOR_RED << "[binary request body]" << ANSI_COLOR_RESET;
    }
    out << std::endl
        << ANSI_COLOR_BLUE
        << parser.response_header
        << ANSI_COLOR_RESET;
    if (parser.response_body.empty()) {
        out << ANSI_COLOR_RED << "[empty response body]" << ANSI_COLOR_RESET;
    } else if (!is_atty || is_plain_text(parser.response_body)) {
        out << parser.response_body;
    } else {
        out << ANSI_COLOR_RED << "[binary response body]" << ANSI_COLOR_RESET;
    }
    return out;
}

std::ofstream& operator<<(std::ofstream& out, const custom_parser& parser) {
    out
        // << parser.request_header
        // << parser.request_body
        // << parser.response_header
        << parser.response_body;
    return out;
    // if(parser.url == "/"){

    // }
    // return out;
}
