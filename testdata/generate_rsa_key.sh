#! /bin/bash

# 生成 pkcs1 私钥
openssl genrsa -out private_key.key 2048
# 私钥 pkcs1 转 pkcs8
openssl pkcs8 -topk8 -inform PEM -in private_key.key -outform pem -nocrypt -out private_key_pkcs8.pem

# 获取公钥
openssl rsa -in private_key.key -pubout -out public_key.pub
# 获取公钥 pkcs8
openssl rsa -in private_key_pkcs8.pem -pubout -out public_key_pkcs8.pem

# ec256, ec384, ec512