test:
	go run main.go format.go -test -debug

run:
	go run main.go format.go 

rund:
	go run main.go format.go -debug

.PHONY: run rund test
