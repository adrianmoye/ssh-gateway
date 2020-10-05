FROM golang:latest as build_env

WORKDIR /go/src/github.com/adrianmoye/ssh-gateway
COPY . .
RUN go get 
#RUN CGO=0 GOOS=linux go build -a -ldflags "-linkmode external -extldflags -static" -o ssh-gateway
RUN GOOS=linux go build -a -ldflags "-linkmode external -extldflags -static" -o ssh-gateway
RUN chmod 755 ssh-gateway

FROM scratch
COPY --from=0 /go/src/github.com/adrianmoye/ssh-gateway/ssh-gateway /

