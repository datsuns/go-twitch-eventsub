test:
	go run main.go format.go config.go -test -debug

run:
	go run main.go format.go config.go 

rund:
	go run main.go format.go config.go -debug

clean:
	rm *.txt

.PHONY: run rund test
