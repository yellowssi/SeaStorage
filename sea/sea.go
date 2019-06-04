// Copyright © 2019 yellowsea <hh1271941291@gmail.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package sea provides the client platform for sea.
package sea

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"path"
	"sync"
	"syscall"

	"github.com/libp2p/go-libp2p"
	p2pCrypto "github.com/libp2p/go-libp2p-core/crypto"
	p2pPeer "github.com/libp2p/go-libp2p-core/peer"
	p2pDHT "github.com/libp2p/go-libp2p-kad-dht"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/sirupsen/logrus"
	tpCrypto "github.com/yellowssi/SeaStorage-TP/crypto"
	tpPayload "github.com/yellowssi/SeaStorage-TP/payload"
	tpSea "github.com/yellowssi/SeaStorage-TP/sea"
	"github.com/yellowssi/SeaStorage/lib"
	"github.com/yellowssi/SeaStorage/p2p"
)

// Client provides the platform for sea providing the storage resources in the P2P network.
type Client struct {
	Sea *tpSea.Sea
	*lib.ClientFramework
}

// NewSeaClient is the construct for Sea Client.
func NewSeaClient(name, keyFile string) (*Client, error) {
	c, err := lib.NewClientFramework(name, lib.ClientCategorySea, keyFile)
	if err != nil {
		return nil, err
	}
	cli := &Client{ClientFramework: c}
	return cli, nil
}

// SeaRegister register the sea in the blockchain.
func (c *Client) SeaRegister() error {
	err := c.Register(c.Name)
	if err != nil {
		return err
	}
	lib.Logger.WithFields(logrus.Fields{
		"name":       c.Name,
		"public key": c.GetPublicKey(),
		"address":    c.GetAddress(),
	}).Info("sea register success")
	return c.Sync()
}

// Sync get the sea's data from blockchain.
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

// Bootstrap start the node process for providing storage resources.
func (c *Client) Bootstrap(keyFile, storagePath string, size int64, bootstrapAddrs []ma.Multiaddr) {
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
		peerInfo, err := p2pPeer.AddrInfoFromP2pAddr(addr)
		if err != nil {
			lib.Logger.WithFields(logrus.Fields{
				"peer": addr,
			}).Warn("failed to get peer info:", err)
			continue
		}
		wg.Add(1)
		go func(info p2pPeer.AddrInfo) {
			defer wg.Done()
			err = host.Connect(ctx, info)
			if err != nil {
				lib.Logger.WithFields(logrus.Fields{
					"peer": peerInfo,
				}).Warn("failed to connect peer:", err)
			}
		}(*peerInfo)
	}
	wg.Wait()
	_, err = p2p.NewSeaNode(ctx, c.ClientFramework, storagePath, size, host, kadDHT)
	if err != nil {
		lib.Logger.Error(err)
		return
	}
	lib.Logger.WithFields(logrus.Fields{
		"listen address":    lib.ListenAddress,
		"listen listenPort": lib.ListenPort,
		"peer id":           host.ID().String(),
	}).Info("Sea Storage start working")
	fmt.Println("Enter Ctrl+C to stop")
	go func() {
		var data []byte
		for {
			data = <-c.State
			s, err := tpSea.SeaFromBytes(data)
			if err != nil {
				lib.Logger.Errorf("failed to sync: %v", err)
			} else {
				c.Sea = s
			}
			c.ConfirmSeaOperations()
		}
	}()
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
}

// ConfirmSeaOperations get the sea's operations from blockchain and operate them.
func (c *Client) ConfirmSeaOperations() {
	if len(c.Sea.Operations) > 0 {
		operations := make([]tpSea.Operation, 0)
		for _, operation := range c.Sea.Operations {
			target := path.Join(lib.StoragePath, operation.Owner)
			operations = append(operations, operation)
			switch operation.Action {
			case tpSea.ActionUserDelete:
				if operation.Shared {
					target = path.Join(target, "shared", operation.Hash)
				} else {
					target = path.Join(target, "home", operation.Hash)
				}
				err := os.Remove(target)
				if err != nil {
					lib.Logger.Error("failed to remove file: ", target)
				}
			case tpSea.ActionUserShared:
				src := path.Join(target, "home", operation.Hash)
				dst := path.Join(target, "shared", operation.Hash)
				err := lib.Copy(src, dst)
				if err != nil {
					lib.Logger.WithFields(logrus.Fields{"src": src, "dst": dst}).Error("failed to copy file:", err)
				}
			case tpSea.ActionGroupDelete:
				// TODO: Group Action
			case tpSea.ActionGroupShared:
			}
		}
		err := c.sendSeaOperations(operations)
		if err != nil {
			lib.Logger.Errorf("failed to send transaction: %v", err)
			return
		}
		lib.Logger.Info("confirm sea operation transaction sent success")
		c.Sea.RemoveOperations(operations)
	}
}

// sendSeaOperations send transactions for confirming sea's operations.
func (c *Client) sendSeaOperations(operations []tpSea.Operation) error {
	payload := tpPayload.SeaStoragePayload{
		Name:          c.Name,
		Action:        tpPayload.SeaConfirmOperations,
		SeaOperations: operations,
	}
	addresses := []string{c.GetAddress()}
	return c.SendTransactionAndWaiting([]tpPayload.SeaStoragePayload{payload}, addresses, addresses)
}
