package p2p

import (
	"context"
	"github.com/libp2p/go-libp2p"
	host "github.com/libp2p/go-libp2p-host"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"testing"
)

var ctx context.Context
var testHost host.Host
var kadDHT *dht.IpfsDHT

func init() {
	var err error
	ctx = context.Background()
	testHost, err = libp2p.New(ctx, libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/55555"))
	if err != nil {
		panic(err)
	}
	kadDHT, err = dht.New(ctx, testHost)
	if err != nil {
		panic(err)
	}
	if err = kadDHT.Bootstrap(ctx); err != nil {
		panic(err)
	}
}

func TestP2P(t *testing.T) {
}
