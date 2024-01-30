test:
	go run main.go format.go config.go -test -debug

run:
	go run main.go format.go config.go 

rund:
	go run main.go format.go config.go -debug

.PHONY: run rund test
