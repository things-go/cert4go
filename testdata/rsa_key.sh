#! /bin/bash

openssl genrsa -out auth_key 2048
openssl rsa -in auth_key -pubout -out auth_key.pub

// ec256, ec384, ec512