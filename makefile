SRC := main.go format.go config.go request.go log.go table.go stats.go watcher.go obs.go

test:
	go test -v

autotest:
	autocmd -v -t '.*\.go' -t 'makefile' -- make test

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
