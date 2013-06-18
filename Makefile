all: ovaultd

ovaultd: *.go
	go get github.com/lib/pq
	go build

setcap: vaultd
	setcap 'CAP_NET_BIND_SERVICE=+ei' vaultd

clean:
	go clean

install:
	mkdir -p $$GOPATH/src/github.com/hdonnay
	ln -s `pwd` $$GOPATH/src/github.com/hdonnay/ovaultd
	go install github.com/hdonnay/ovaultd
