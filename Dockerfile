FROM golang:latest as build_env

WORKDIR /go/src/github.com/adrianmoye/ssh-gateway
COPY . .
RUN go get 
RUN GOOS=linux GOARCH=$GOARCH go build -a -ldflags "-linkmode external -extldflags -static" -o ssh-gateway
RUN chmod 755 ssh-gateway

FROM scratch
COPY --from=build_env /go/src/github.com/adrianmoye/ssh-gateway/ssh-gateway /
