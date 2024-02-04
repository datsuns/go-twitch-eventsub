SRC := main.go format.go config.go request.go log.go table.go stats.go

test:
	go test -v

local:
	go run $(SRC) -test

locald:
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
	cp ./twichevent.exe ../../../test

.PHONY: test testd run rund clean
