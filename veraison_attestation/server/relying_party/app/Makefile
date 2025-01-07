BINARY_NAME=rp

all: run

build: main.go
	go build -o $(BINARY_NAME) main.go

run: build
	./$(BINARY_NAME)

clean:
	rm -rf $(BINARY_NAME)
