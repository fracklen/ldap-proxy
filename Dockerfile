FROM golang:1.7.4-alpine

RUN apk update && apk add git

ADD . /app
WORKDIR /app
RUN go get
RUN mkdir /data

ENTRYPOINT ["go", "run", "proxy.go"]
