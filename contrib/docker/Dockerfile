FROM docker.io/golang:alpine as builder

COPY . /src
WORKDIR /src

ENV CGO_ENABLED=0

RUN apk add git && ./build && go build -o /src/genkeys cmd/genkeys/main.go

FROM docker.io/alpine

COPY --from=builder /src/ruvchain /usr/bin/ruvchain
COPY --from=builder /src/ruvchainctl /usr/bin/ruvchainctl
COPY --from=builder /src/genkeys /usr/bin/genkeys
COPY contrib/docker/entrypoint.sh /usr/bin/entrypoint.sh

# RUN addgroup -g 1000 -S ruvcoindev \
#  && adduser -u 1000 -S -g 1000 --home /etc/ruvcoindev ruvcoindev
#
# USER ruvcoindev
# TODO: Make running unprivileged work

VOLUME [ "/etc/ruvcoindev" ]

ENTRYPOINT [ "/usr/bin/entrypoint.sh" ]
