all:
	go build -o vaultd

debug: vaultd
	go build -v -race -o vaultd
