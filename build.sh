#!/bin/bash

set -e

docker run --rm \
    --name build-cert-lifetime-exporter \
    -v $PWD:/usr/src/cert-lifetime-exporter \
    -w /usr/src/cert-lifetime-exporter \
    golang:1.9-alpine go build -v

docker build -t cert-lifetime-exporter .