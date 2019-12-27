FROM golang:1.12 as builder

WORKDIR /build
ENV GO111MODULE=on
COPY go* /build/
# do this in a separate layer to cache deps from build to build
#RUN go get
ADD . .
RUN CGO_ENABLED=0 GOOOS=linux go build  -o ext-auth-poc /build/cmd/tlsjwtgw/*.go


FROM alpine:latest
LABEL maintainer="fams@linuxplace.com.br"
WORKDIR /
RUN apk update && apk add ca-certificates && rm -rf /var/cache/apk/*
COPY --from=builder /build/ext-auth-poc .
CMD ["./ext-auth-poc"]