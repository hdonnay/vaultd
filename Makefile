all: ovaultd

ovaultd: *.go
	@go get github.com/lib/pq
	@go get github.com/gokyle/cryptobox/box
	@go get github.com/emicklei/go-restful
	@go get github.com/golang/glog
	@go fmt
	@go build

setcap: ovaultd
	setcap 'CAP_NET_BIND_SERVICE=+ei' vaultd

pack: ovaultd
	@goupx ovaultd

clean:
	go clean

install:
	mkdir -p $$GOPATH/src/github.com/hdonnay
	ln -s `pwd` $$GOPATH/src/github.com/hdonnay/ovaultd
	go install github.com/hdonnay/ovaultd

debug: ovaultd
	 ./ovaultd -logtostderr -v=3 -stderrthreshold=3

.PHONY: test clean setcap pack
