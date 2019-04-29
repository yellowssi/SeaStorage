package p2p

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

func SeaHandler(priv, listenHost string, listenPort int) {
	privateKey, err := crypto.UnmarshalSecp256k1PrivateKey(crypto2.HexToBytes(priv))
	if err != nil {
		panic(err)
	}
	ctx := context.Background()
	sourceMultiAddr, _ := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/%s/tcp/%d", listenHost, listenPort))
	host, err := libp2p.New(ctx, libp2p.ListenAddrs(sourceMultiAddr), libp2p.Identity(privateKey))
	if err != nil {
		panic(err)
	}
	host.SetStreamHandler(protocol.ID(lib.ProtocolID), seaHandleStream)

	publicKeyBytes, err := privateKey.GetPublic().Bytes()
	if err != nil {
		panic(err)
	}
	peerChan := initMDNS(ctx, host, crypto2.BytesToHex(publicKeyBytes))
	peer := <-peerChan
	stream, err := host.NewStream(ctx, peer.ID, protocol.ID(lib.ProtocolID))
	if err != nil {
		fmt.Println("Stream open failed:", err)
	} else {
		rw := bufio.NewReadWriter(bufio.NewReader(stream), bufio.NewWriter(stream))

		go seaWriteData(rw)
		go seaReadData(rw)
		fmt.Println("Connected to:", peer)
	}

	select {}
}

func seaHandleStream(s inet.Stream) {
	rw := bufio.NewReadWriter(bufio.NewReader(s), bufio.NewWriter(s))

	go seaReadData(rw)
	go seaWriteData(rw)
}

func seaReadData(rw *bufio.ReadWriter) {

}

func seaWriteData(rw *bufio.ReadWriter) {

}
