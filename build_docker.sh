#!/bin/bash


docker build . -t adrianmoye/ssh-gateway:latest
#docker build -e GOARCH=amd64 . -t adrianmoye/ssh-gateway:latest

