all: ovaultd

ovaultd: *.go
	go get github.com/lib/pq
	go get github.com/gokyle/cryptobox/box
	go get github.com/emicklei/go-restful
	go build

setcap: vaultd
	setcap 'CAP_NET_BIND_SERVICE=+ei' vaultd

clean:
	go clean

install:
	mkdir -p $$GOPATH/src/github.com/hdonnay
	ln -s `pwd` $$GOPATH/src/github.com/hdonnay/ovaultd
	go install github.com/hdonnay/ovaultd

test: ovaultd
	./ovaultd -forceInsecure

.PHONY: test clean setcap
