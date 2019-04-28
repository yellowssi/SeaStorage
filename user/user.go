package user

import (
	"gitlab.com/SeaStorage/SeaStorage-TP/payload"
	"gitlab.com/SeaStorage/SeaStorage-TP/storage"
	seaStorageUser "gitlab.com/SeaStorage/SeaStorage-TP/user"
	"gitlab.com/SeaStorage/SeaStorage/crypto"
	"gitlab.com/SeaStorage/SeaStorage/lib"
	"path"
	"strings"
)

type Client struct {
	User            *seaStorageUser.User
	PWD             string
	ClientFramework *lib.ClientFramework
}

func NewUserClient(name string, url string, keyFile string) (*Client, error) {
	c, err := lib.NewClient(name, lib.ClientCategoryUser, url, keyFile)
	if err != nil {
		return nil, err
	}
	u, _ := c.Show()
	return &Client{User: u, PWD: "/", ClientFramework: c}, nil
}

func (c *Client) Register() (err error) {
	_, err = c.ClientFramework.Register(c.ClientFramework.Name)
	if err != nil {
		return err
	}
	return c.Sync()
}

func (c *Client) ChangePWD(dst string) error {
	if !strings.HasPrefix(dst, "/") {
		dst = path.Join(c.PWD, dst)
	}
	if !strings.HasSuffix(dst, "/") {
		dst += "/"
	}
	_, err := c.User.Root.GetDirectory(dst)
	if err != nil {
		return err
	}
	c.PWD = dst
	return nil
}

func (c *Client) CreateDirectory(p string) (map[interface{}]interface{}, error) {
	if !strings.HasPrefix(p, "/") {
		p = path.Join(c.PWD, p)
	}
	if !strings.HasSuffix(p, "/") {
		p += "/"
	}
	err := c.User.Root.CreateDirectory(p)
	if err != nil {
		return nil, err
	}
	response, err := c.ClientFramework.SendTransaction([]payload.SeaStoragePayload{{
		Action: payload.UserCreateDirectory,
		Name:   c.ClientFramework.Name,
		PWD:    p,
	}}, lib.DefaultWait)
	return response, err
}

func (c *Client) CreateFile(target, p string, dataShards, parShards int) (map[interface{}]interface{}, error) {
	info, err := crypto.GenerateFileInfo(target, dataShards, parShards)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(p, "/") {
		p = path.Join(c.PWD, p)
	}
	if !strings.HasSuffix(p, "/") {
		p += "/"
	}
	err = c.User.Root.CreateFile(p, info)
	if err != nil {
		return nil, err
	}
	response, err := c.ClientFramework.SendTransaction([]payload.SeaStoragePayload{{
		Action:   payload.UserCreateFile,
		Name:     c.ClientFramework.Name,
		PWD:      p,
		FileInfo: info,
	}}, lib.DefaultWait)
	return response, err
}

func (c *Client) ListDirectory(p string) ([]storage.INodeInfo, error) {
	if !strings.HasPrefix(p, "/") {
		p = path.Join(c.PWD, p)
	}
	if !strings.HasSuffix(p, "/") {
		p += "/"
	}
	return c.User.Root.ListDirectory(p)
}

func (c *Client) Sync() error {
	u, err := c.ClientFramework.Show()
	if err != nil {
		return err
	}
	c.User = u
	return nil
}
