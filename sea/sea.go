package sea

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/libp2p/go-libp2p"
	p2pCrypto "github.com/libp2p/go-libp2p-crypto"
	p2pDHT "github.com/libp2p/go-libp2p-kad-dht"
	p2pPeerstore "github.com/libp2p/go-libp2p-peerstore"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/sirupsen/logrus"
	tpCrypto "gitlab.com/SeaStorage/SeaStorage-TP/crypto"
	tpSea "gitlab.com/SeaStorage/SeaStorage-TP/sea"
	"gitlab.com/SeaStorage/SeaStorage/lib"
	"gitlab.com/SeaStorage/SeaStorage/p2p"
)

type Client struct {
	Sea *tpSea.Sea
	*lib.ClientFramework
}

func NewSeaClient(name, keyFile string) (*Client, error) {
	c, err := lib.NewClientFramework(name, lib.ClientCategorySea, keyFile)
	if err != nil {
		return nil, err
	}
	cli := &Client{ClientFramework: c}
	_ = cli.Sync()
	return cli, nil
}

func (c *Client) SeaRegister() error {
	_, err := c.Register(c.Name)
	if err != nil {
		return err
	}
	lib.Logger.WithFields(logrus.Fields{
		"name":       c.Name,
		"public key": c.GetPublicKey(),
		"address":    c.GetAddress(),
	}).Info("sea register success")
	go func() {
		time.Sleep(time.Minute)
		c.Sync()
	}()
	return nil
}

func (c *Client) Sync() error {
	seaBytes, err := c.GetData()
	if err != nil {
		return err
	}
	s, err := tpSea.SeaFromBytes(seaBytes)
	if err != nil {
		return err
	}
	c.Sea = s
	return nil
}

func (c Client) Bootstrap(keyFile, storagePath string, size int64, bootstrapAddrs []ma.Multiaddr) {
	priv, _ := ioutil.ReadFile(keyFile)
	privateKey, err := p2pCrypto.UnmarshalSecp256k1PrivateKey(tpCrypto.HexToBytes(string(priv)))
	if err != nil {
		lib.Logger.Error(err)
		return
	}
	multiAddr, err := ma.NewMultiaddr(fmt.Sprintf("/ip4/%s/tcp/%d", lib.ListenAddress, lib.ListenPort))
	if err != nil {
		lib.Logger.Error(err)
		return
	}
	ctx := context.Background()
	host, err := libp2p.New(ctx, libp2p.ListenAddrs(multiAddr), libp2p.Identity(privateKey))
	if err != nil {
		lib.Logger.Error(err)
		return
	}
	_, err = p2p.NewSeaNode(c.ClientFramework, storagePath, size, host)
	if err != nil {
		lib.Logger.Error(err)
		return
	}
	kadDHT, err := p2pDHT.New(ctx, host)
	if err != nil {
		lib.Logger.Error(err)
		return
	}
	if err = kadDHT.Bootstrap(ctx); err != nil {
		lib.Logger.Error(err)
		return
	}
	var wg sync.WaitGroup
	for _, addr := range bootstrapAddrs {
		peerInfo, err := p2pPeerstore.InfoFromP2pAddr(addr)
		if err != nil {
			lib.Logger.WithFields(logrus.Fields{
				"peer": addr,
			}).Warn("failed to get peer info:", err)
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			err = host.Connect(ctx, *peerInfo)
			if err != nil {
				lib.Logger.WithFields(logrus.Fields{
					"peer": peerInfo,
				}).Warn("failed to connect peer:", err)
			}
		}()
	}
	wg.Wait()
	lib.Logger.WithFields(logrus.Fields{
		"listen address":    lib.ListenAddress,
		"listen listenPort": lib.ListenPort,
		"peer id":           host.ID().String(),
	}).Info("Sea Storage start working")
	fmt.Println("Enter Ctrl+C to stop")
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
}
