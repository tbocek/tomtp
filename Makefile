.PHONY: all dep build test clean

all: dep build test

dep:
	go mod download
build:
	go build
test:
	go test
clean:
	go clean
	go mod tidy
