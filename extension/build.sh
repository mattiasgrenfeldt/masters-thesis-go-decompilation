#!/bin/bash
GOOS=linux   GOARCH=amd64 go build -C goretk_util -o ../os/linux_x86_64/goretk_util .
GOOS=windows GOARCH=amd64 go build -C goretk_util -o ../os/win_x86_64/goretk_util.exe .
GOOS=darwin  GOARCH=amd64 go build -C goretk_util -o ../os/mac_x86_64/goretk_util .
rm -rf dist/
gradle
