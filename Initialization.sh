#!/bin/sh
crtpath=`pwd`
CAshpath="/usr/lib/ssl/misc/CA.sh"
if [ ! -d ${crtpath}"/openssl" ]; then
    mkdir openssl
else
    echo "Directory openssl has existed!"
    exit 0;
fi
if [ -f "$CAshpath" ]; then
    cp $CAshpath ${crtpath}"/openssl"
else
    echo ${CAshpath}"not exists"
fi
#生成CA管理目录及根私钥和根证书
cd ./openssl
./CA.sh -newca
#生成服务器私钥
openssl genrsa -des3 -out server.key 1024
#生成服务器证书请求
openssl req -new -key server.key -out server.csr
#CA签发服务器证书
openssl ca -in server.csr -out server.crt
