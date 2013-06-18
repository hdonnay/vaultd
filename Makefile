all: vaultd

vaultd: *.go
	go get github.com/lib/pq
	go build -o vaultd

setcap: vaultd
	setcap 'CAP_NET_BIND_SERVICE=+ei' vaultd
