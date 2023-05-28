# httpflow
A copy from [httpflow-annotation-cyh](https://github.com/cherry-cheng/httpflow-annotation-cyh)

Origin repos in [httpflow](https://github.com/six-ddc/httpflow)

# Installation
You can build this project by
```bash
## On Ubuntu / Debian
apt-get update
apt-get install libpcap-dev zlib1g-dev libpcre3 libpcre3-dev
./run.sh -b
# or make
```

# Usage
when success, a **httpflow** executable file generate in your project root. run
```bash
sudo ./httpflow
```
to execute it. Or you can use
```bash
./run.sh -s httpflow # change permission
./httpflow # execute without sudo. It will be convienced for debugging
```
to change the file's permission and run without sudo.

By default, it output to your terminal. You can use `-w` option to specify the output directory.
```bash
./httpflow -w ./html/
```
Please refer to [httpflow](https://github.com/six-ddc/httpflow) for more information/help.


You can run the following command for more information:
```bash
> ./httpflow -h
libpcap version libpcap version 1.10.1 (with TPACKET_V3)
httpflow version 0.0.5

Usage: httpflow [-i interface | -r pcap-file] [-f packet-filter] [-u url-filter] [-w output-path]

  -i interface      Listen on interface
  -r pcap-file      Read packets from file (which was created by tcpdump with the -w option)
                    Standard input is used if file is '-'
  -f packet-filter  Selects which packets will be dumped
                    If filter expression is given, only packets for which expression is 'true' will be dumped
                    For the expression syntax, see pcap-filter(7)
  -u url-filter     Matches which urls will be dumped
  -w output-path    Write the http request and response to a specific directory

  For more information, see https://github.com/six-ddc/httpflow


> ./run.sh -h
Usage: ./run.sh [option]
  b - build this project. you will got a 'httpflow' in your project directory.
  s - [httpflow_pos] change ‘httpflow’ permissions to root.(Execute without sudo).
  m - [output_pos] change the owner of 'output directory' to you.
  h - print this message.
```

# Example
When you have installed httpflow. You can try it to capture a html file as the example shown below
```bash
> ./httpflow ./html

# Another terminal
> curl www.baidu.com
> curl www.baidu.com/home

# there will generate a new folder named 'html' whose directory struct looks like this 
> tree html
html
└── www.baidu.com
    ├── home
    │   └── index.html
    └── index.html

```





