package sea

import (
	"github.com/sirupsen/logrus"
	tpSea "gitlab.com/SeaStorage/SeaStorage-TP/sea"
	"gitlab.com/SeaStorage/SeaStorage/lib"
)

type Client struct {
	Sea *tpSea.Sea
	*lib.ClientFramework
}

func NewClient(name, url, keyFile string) (*Client, error) {
	c, err := lib.NewClientFramework(name, lib.ClientCategorySea, url, keyFile)
	if err != nil {
		return nil, err
	}
	var s *tpSea.Sea
	seaBytes, _ := c.GetData()
	if seaBytes != nil {
		logrus.WithField("seaname", name).Info("sea login success")
		s, err = tpSea.SeaFromBytes(seaBytes)
		if err != nil {
			s = nil
			logrus.Error(err)
		}
	}
	return &Client{Sea: s, ClientFramework: c}, nil
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
