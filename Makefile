build:
	gofumpt -w *.go
	go build -o rpkirtr

cover:
	go test -cover ./...

race:
	go test -race
