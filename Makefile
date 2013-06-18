all: vaultd

vaultd: *.go
	go build -o vaultd

setcap: vaultd
	setcap 'CAP_NET_BIND_SERVICE=+ei' vaultd
