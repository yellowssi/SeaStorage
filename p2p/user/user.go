package user

import (
	"bufio"
	"context"
	"fmt"
	"github.com/libp2p/go-libp2p"
	crypto "github.com/libp2p/go-libp2p-crypto"
	inet "github.com/libp2p/go-libp2p-net"
	protocol "github.com/libp2p/go-libp2p-protocol"
	"github.com/multiformats/go-multiaddr"
	crypto2 "gitlab.com/SeaStorage/SeaStorage-TP/crypto"
	"gitlab.com/SeaStorage/SeaStorage/lib"
)

func UserHandler(priv, listenHost string, listenPort int) {
	privateKey, err := crypto.UnmarshalSecp256k1PrivateKey(crypto2.HexToBytes(priv))
	if err != nil {
		panic(err)
	}
	sourceMultiAddr, _ := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/%s/tcp/%d", listenHost, listenPort))
	host, err := libp2p.New(context.Background(), libp2p.ListenAddrs(sourceMultiAddr), libp2p.Identity(privateKey))
	if err != nil {
		panic(err)
	}
	host.SetStreamHandler(protocol.ID(lib.ProtocolID), handleStream)
}

func handleStream(s inet.Stream) {
	rw := bufio.NewReadWriter(bufio.NewReader(s), bufio.NewWriter(s))

	go readData(rw)
	go writeData(rw)
}

func readData(rw *bufio.ReadWriter) {

}

func writeData(rw *bufio.ReadWriter) {

}
