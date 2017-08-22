# httpflow-annotation-cyh
description of httpflow
得到了httpflow作者大神的回应，对于这个http协议的抓取代码有了更进一步的了解。
可以从main方法开始看，主要逻辑是使用pcap库捕获包，然后按照ip-》tcp-》http协议依次解包，
再使用http_parser解析http,最后按照一定格式输出打印。
感谢 dongcheng.du大神
