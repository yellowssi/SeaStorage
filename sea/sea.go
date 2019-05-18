package sea

import (
	"github.com/sirupsen/logrus"
	tpSea "gitlab.com/SeaStorage/SeaStorage-TP/sea"
	"gitlab.com/SeaStorage/SeaStorage/lib"
	"gitlab.com/SeaStorage/SeaStorage/p2p"
	"io/ioutil"
	"os"
	"os/signal"
	"syscall"
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

func (c Client) Bootstrap(keyFile, storagePath string, size int64, listenAddress string, port int) {
	privateKey, _ := ioutil.ReadFile(keyFile)
	_, err := p2p.NewSeaNode(c.ClientFramework, storagePath, size, listenAddress, port, privateKey)
	if err != nil {
		logrus.Error(err)
		return
	}
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
	logrus.Info("Exit")
}
