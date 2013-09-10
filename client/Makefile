all: vault

vault: vault.go
	go get code.google.com/p/go.crypto/ssh/terminal
	go get github.com/gokyle/cryptobox/box
	go get github.com/gokyle/cryptobox/secretbox
	go build -o vault

test: vault
	./vault -forceUnencrypted -username=defaultAdmin -debug -keyPath="`pwd`/" test

.PHONY: test
