#!/bin/sh -x
export CGO_ENABLED=0 GOFLAGS=-ldflags=-checklinkname=0 
go build -o hyrealm2wg .
GOOS=linux GOARCH=amd64 go build -o hyrealm2wg_linux-gnu_amd64 .
GOOS=linux GOARCH=arm64 go build -o hyrealm2wg_linux-gnu_arm64 .
GOOS=android GOARCH=arm64 go build -o hyrealm2wg_linux-android_arm64 .
