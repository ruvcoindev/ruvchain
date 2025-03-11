# Git cloning
FROM		debian:bullseye-slim AS code-cloner

WORKDIR		/src

RUN			apt-get update && apt-get install -y git 
RUN			git clone https://github.com/ruvcoindev/ruvchain


# Compiling
FROM		golang:1.17-alpine AS builder
ENV			CGO_ENABLED 0
ENV			TZ=Europe/Moscow

COPY		--from=code-cloner /src /src
WORKDIR		/src/ruvchain
RUN			./build && rm -rf /root /go


# Compressing binary
FROM		gruebel/upx:latest as upx
COPY		--from=builder /src/ruvchain/ruvchain /app.fat
COPY		--from=builder /src/ruvchain/ruvchainctl /appctl.fat
RUN			upx --best --lzma -o /ruvchain /app.fat
RUN			upx --best --lzma -o /ruvchainctl /appctl.fat


# Intermidate image
# Compressing layers
FROM		alpine as inter

COPY		--from=upx /ruvchain /ruvchain
COPY		--from=upx /ruvchainctl /ruvchainctl
COPY		--from=builder /var /var
COPY		--from=builder /run /run
COPY		entrypoint.sh /entrypoint.sh


# Final image
FROM		scratch

COPY		--from=inter / /

VOLUME		[ "/config" ]
ENTRYPOINT	[ "sh", "/entrypoint.sh" ]
