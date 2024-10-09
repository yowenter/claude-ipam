 

FROM golang:1.20.7 AS builder


COPY . /src
WORKDIR /src

RUN make build



FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
		ca-certificates


WORKDIR /claude
COPY --from=builder /src/bin/  /claude
COPY script/install_cni.sh  /claude/


EXPOSE 8080
CMD ["/claude/ipam-server"]




