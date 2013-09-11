all: vault

vault: vault.go
	@go get code.google.com/p/go.crypto/ssh/terminal
	@go get github.com/gokyle/cryptobox/box
	@go get github.com/gokyle/cryptobox/secretbox
	@go fmt
	@go build -o vault

test: vault
	XDG_CONFIG_HOME=`pwd`/test ./vault -debug -username=defaultAdmin test

pack: vault
	@goupx vault

.PHONY: test pack
