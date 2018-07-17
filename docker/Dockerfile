FROM alpine

RUN apk add --no-cache git g++ openssl-dev

RUN git clone --recursive https://github.com/mmlr/teleport

WORKDIR /teleport

RUN ./build.sh

ENTRYPOINT ["./teleport"]
