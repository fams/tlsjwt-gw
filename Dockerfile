FROM golang:latest as builder

WORKDIR /build
ENV GO111MODULE=on
COPY go* /build/
# do this in a separate layer to cache deps from build to build
#RUN go get
ADD . .
RUN CGO_ENABLED=0 GOOOS=linux go build  -o ext-auth-poc /build/cmd/jwtgw/*.go


FROM alpine:latest
WORKDIR /
COPY --from=builder /build/ext-auth-poc .
CMD ["./ext-auth-poc"]
