package user

import (
	"gitlab.com/SeaStorage/SeaStorage-Client/lib"
	seaStorageUser "gitlab.com/SeaStorage/SeaStorage/user"
	"os/user"
	"path"
)

type UserClient struct {
	User   *seaStorageUser.User
	Client lib.Client
}

func NewUserClient(name string, url string, keyFile string) (*UserClient, error) {
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
	return &UserClient{nil, c}, nil
}

func GetKeyFilePath() string {
	username, err := user.Current()
	if err != nil {
		return "./SeaStorage.priv"
	}
	return path.Join(username.HomeDir, ".SeaStorage", "keys", username.Username+".priv")
}

func Register(name string, url string, keyFile string) (c *UserClient, err error) {
	if keyFile == "" {
		lib.GenerateKey(lib.FamilyName, lib.DefaultKeyFilePath)
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
	_, err = c.Client.Register(name)
	if err != nil {
		return nil, err
	}
	u, err := c.Client.Show()
	if err != nil {
		return nil, err
	}
	c.User = u
	return c, nil
}
