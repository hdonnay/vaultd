all: vaultd

vaultd: *.go
	@go get github.com/lib/pq
	@go get github.com/gokyle/cryptobox/box
	@go get github.com/emicklei/go-restful
	@go get github.com/golang/glog
	@go fmt
	@go build

setcap: vaultd
	setcap 'CAP_NET_BIND_SERVICE=+ei' vaultd

pack: vaultd
	@goupx vaultd

clean:
	go clean

install:
	mkdir -p $$GOPATH/src/github.com/hdonnay
	ln -s `pwd` $$GOPATH/src/github.com/hdonnay/ovaultd
	go install github.com/hdonnay/ovaultd

debug: vaultd
	 ./vaultd -logtostderr -v=3 -stderrthreshold=3

.PHONY: test clean setcap pack
