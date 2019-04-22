package user

import (
	"gitlab.com/SeaStorage/SeaStorage-Client/lib"
	"gitlab.com/SeaStorage/SeaStorage/storage"
	seaStorageUser "gitlab.com/SeaStorage/SeaStorage/user"
	"os/user"
	"path"
)

type Client struct {
	User            *seaStorageUser.User
	ClientFramework lib.ClientFramework
}

func NewUserClient(name string, url string, keyFile string) (*Client, error) {
	if url == "" {
		url = lib.DefaultUrl
	}
	if keyFile == "" {
		keyFile = GetKeyFilePath()
	}
	c, err := lib.NewClient(name, lib.ClientCategoryUser, url, keyFile)
	if err != nil {
		return nil, err
	}
	return &Client{nil, c}, nil
}

func GetKeyFilePath() string {
	username, err := user.Current()
	if err != nil {
		return "./" + lib.FamilyName + ".priv"
	}
	return path.Join(username.HomeDir, ".SeaStorage", "keys", username.Username+".priv")
}

func Register(name string, url string, keyFile string) (c *Client, err error) {
	if keyFile == "" {
		lib.GenerateKey(lib.FamilyName, GetKeyFilePath())
		c, err = NewUserClient(name, url, keyFile)
		if err != nil {
			return nil, err
		}
	} else {
		c, err = NewUserClient("", url, keyFile)
		if err != nil {
			return nil, err
		}
	}
	_, err = c.ClientFramework.Register(name)
	if err != nil {
		return nil, err
	}
	u, err := c.ClientFramework.Show()
	if err != nil {
		return nil, err
	}
	c.User = u
	return c, nil
}

func (c Client) CreateDirectory() (map[interface{}]interface{}, error) {

}

func (c Client) CreateFile() (map[interface{}]interface{}, error) {

}

func (c Client) UpdateName() (map[interface{}]interface{}, error) {

}

func (c Client) UpdateFileInfo() (map[interface{}]interface{}, error) {

}

func (c Client) UpdateFileKey() (map[interface{}]interface{}, error) {

}

func (c Client) ShareFiles() (map[interface{}]interface{}, error) {

}

func (c Client) PublicKey() (map[interface{}]interface{}, error) {

}

func (c Client) ListDirectory() ([]storage.INodeInfo, error) {

}

func (c Client) GetFiles() error {

}
