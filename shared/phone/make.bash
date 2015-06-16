#!/usr/bin/env bash
# Copyright 2014 The Go Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

set -e

if [ ! -f make.bash ]; then
	echo 'make.bash must be run from $GOPATH/src/golang.org/x/mobile/example/libhello'
	exit 1
fi

# New stuff here.
mkdir -p xault/go_xault
gobind -lang=go github.com/runningwild/xault/shared/phone/xault > xault/go_xault/go_xault.go
rm -rf ../../android/Xault/app/src/main/java/go
mkdir -p ../../android/Xault/app/src/main/java/go/xault
gobind -lang=java github.com/runningwild/xault/shared/phone/xault > ../../android/Xault/app/src/main/java/go/xault/Xault.java
cp $GOPATH/src/golang.org/x/mobile/app/Go.java ../../android/Xault/app/src/main/java/go/
cp $GOPATH/src/golang.org/x/mobile/bind/java/Seq.java ../../android/Xault/app/src/main/java/go/
mkdir -p ../../android/Xault/app/src/main/jniLibs/armeabi-v7a
CGO_ENABLED=1 GOOS=android GOARCH=arm GOARM=7 go build -ldflags="-shared" -o ../../android/Xault/app/src/main/jniLibs/armeabi-v7a/libgojni.so .

# mkdir -p libs/armeabi-v7a src/go/hi
# ANDROID_APP=$PWD
# (cd ../.. && ln -sf $PWD/app/*.java $ANDROID_APP/src/go)
# (cd ../.. && ln -sf $PWD/bind/java/Seq.java $ANDROID_APP/src/go)
# CGO_ENABLED=1 GOOS=android GOARCH=arm GOARM=7 \
# 	go build -ldflags="-shared" .
# mv -f libhello libs/armeabi-v7a/libgojni.so
# ant debug
