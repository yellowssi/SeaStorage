package sea

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"syscall"

	"github.com/libp2p/go-libp2p"
	p2pCrypto "github.com/libp2p/go-libp2p-crypto"
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
	logrus.WithFields(logrus.Fields{
		"name":       c.Name,
		"public key": c.GetPublicKey(),
		"address":    c.GetAddress(),
	}).Info("sea register success")
	return c.Sync()
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

func (c Client) Bootstrap(keyFile, storagePath string, size int64, listenAddress string, listenPort int) {
	priv, _ := ioutil.ReadFile(keyFile)
	privateKey, err := p2pCrypto.UnmarshalSecp256k1PrivateKey(tpCrypto.HexToBytes(string(priv)))
	if err != nil {
		logrus.Error(err)
		return
	}
	multiAddr, err := ma.NewMultiaddr(fmt.Sprintf("/ip4/%s/tcp/%d", lib.ListenAddress, lib.ListenPort))
	if err != nil {
		logrus.Error(err)
		return
	}
	host, err := libp2p.New(context.Background(), libp2p.ListenAddrs(multiAddr), libp2p.Identity(privateKey))
	if err != nil {
		logrus.Error(err)
		return
	}
	_, err = p2p.NewSeaNode(c.ClientFramework, storagePath, size, host)
	if err != nil {
		logrus.Error(err)
		return
	}
	logrus.WithFields(logrus.Fields{
		"listen address":    listenAddress,
		"listen listenPort": listenPort,
	}).Info("Sea Storage start working")
	fmt.Println("Enter Ctrl+C to stop")
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
	logrus.Info("Exit")
}
