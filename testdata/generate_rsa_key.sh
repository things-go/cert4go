#! /bin/bash

# 生成 pkcs1 私钥
openssl genrsa -out auth_key.key 2048
# 获取公钥
openssl rsa -in auth_key.key -pubout -out auth_key.pub
# pkcs1 转 pkcs8
openssl pkcs8 -topk8 -inform PEM -in auth_key.key -outform pem -nocrypt -out auth_key-pkcs8.pem

# ec256, ec384, ec512