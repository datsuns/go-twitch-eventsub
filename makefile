SRC := main.go format.go config.go

test:
	go run $(SRC) -test

testd:
	go run $(SRC) -test -debug

run:
	go run $(SRC)

rund:
	go run $(SRC) -debug

clean:
	rm *.txt
	*.exe

release:
	go build
	cp ./config.yaml ./go-twitch-eventsub-client.exe ../../../test

.PHONY: test testd run rund clean
