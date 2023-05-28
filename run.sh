#!/bin/bash


set -e # 遇到错误则停止

nproc=$(cat /proc/cpuinfo | grep processor | wc -l)
green='\033[1;32m'
red='\033[1;31m'
end='\033[0m'


KEYGOING(){
    echo -e "${red} ${msg} ${end}"
    echo "Do you want to continue? [y/n]"
    read answer

    if [ "$answer" = "y" ] || [ "$answer" = "Y" ]; then
        echo "Continuing..."
        # 继续执行脚本
    elif [ "$answer" = "n" ] || [ "$answer" = "N" ]; then
        echo "Exiting..."
        exit
    else
        echo "Invalid input!"
        KEYGOING $1
    fi
}

SUDO_FILE(){
    set -x
    sudo chown root:root $1
    sudo chmod u+s $1
    set +x
}


CHANGE_OWNER(){
    # msg="Be Careful! You will change the owner of this directory '$1' to you."
    msg=$(echo "Be Careful! You will change the owner of this directory'" $1 "' to you.")
    KEYGOING
    sudo chown $USER:$USER -R $1
}


BUILD(){
    set -x # 打印出执行的命令
    make clean
    make
    set +x
    echo "*************************"
    echo -e "${green} build success ${end}"
}

HELP(){
    echo "Usage: ./run.sh [option]"
    echo "  b - build this project. you will got a 'httpflow' in your project directory."
    echo "  s - [httpflow_pos] change ‘httpflow’ permissions to root.(Execute without sudo)."
    echo "  m - [output_pos] change the owner of 'output directory' to you."
    echo "  h - print this message."
}


while getopts "bs:m:h" opt; do
    case $opt in
        s) SUDO_FILE $OPTARG && exit  ;;
        m) CHANGE_OWNER $OPTARG && exit ;;
        b) BUILD && exit ;;
        h) HELP  && exit ;;
    esac
done

HELP

