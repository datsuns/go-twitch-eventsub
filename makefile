test:
	go run main.go format.go config.go -test

testd:
	go run main.go format.go config.go -test -debug

run:
	go run main.go format.go config.go 

rund:
	go run main.go format.go config.go -debug

clean:
	rm *.txt
	*.exe

release:
	go build
	cp ./config.yaml ./go-twitch-eventsub-client.exe ../../../test

.PHONY: test testd run rund clean
