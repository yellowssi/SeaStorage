// Copyright © 2019 yellowsea <hh1271941292@gmail.com>
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

package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/user"
	"path"

	ma "github.com/multiformats/go-multiaddr"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/yellowssi/SeaStorage/lib"
)

var (
	version        bool
	cfgFile        string
	name           string
	debug          bool
	bootstrapAddrs []string
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   lib.FamilyName,
	Short: "Decentralized cloud storage application",
	Long: `SeaStorage is a decentralized cloud storage application.
This application is a tool for store files on a P2P
network based on Hyperledger Sawtooth.`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	Run: func(cmd *cobra.Command, args []string) {
		if version {
			fmt.Println("SeaStorage (Decentralized File storage system)")
			fmt.Println("Version: " + lib.FamilyVersion)
			return
		}
		cmd.Help()
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	initConfig()
	cobra.OnInitialize(initLogger)
	cobra.OnInitialize(initBootstrapNodes)

	rootCmd.PersistentFlags().BoolVarP(&version, "version", "v", false, "the version of SeaStorage")
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file(json)")
	rootCmd.PersistentFlags().StringVarP(&name, "name", "n", GetDefaultUsername(), "the name of user/sea")
	rootCmd.PersistentFlags().StringVarP(&lib.TPURL, "url", "u", lib.DefaultTPURL, "the sawtooth rest api")
	rootCmd.PersistentFlags().StringVarP(&lib.PrivateKeyFile, "key", "k", lib.DefaultPrivateKeyFile, "the private key file for identity")
	rootCmd.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "debug version")
	rootCmd.PersistentFlags().StringVarP(&lib.ListenAddress, "listen", "l", lib.DefaultListenAddress, "the listen address for p2p network")
	rootCmd.PersistentFlags().IntVarP(&lib.ListenPort, "port", "p", lib.DefaultListenPort, "the listen port for p2p network")
	rootCmd.PersistentFlags().StringArrayVarP(&bootstrapAddrs, "bootstrap", "b", lib.DefaultBootstrapAddrs, "the bootstrap node addresses of the p2p network")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Search config in home directory with name ".SeaStorage" (without extension).
		viper.AddConfigPath(lib.DefaultConfigPath)
		viper.SetConfigName(lib.DefaultConfigFilename)
		if _, err := os.Stat(path.Join(lib.DefaultConfigPath, lib.DefaultConfigFilename+".json")); os.IsNotExist(err) {
			cf, err := os.Create(path.Join(lib.DefaultConfigPath, lib.DefaultConfigFilename+".json"))
			if err != nil {
				panic(err)
			}
			_, err = cf.Write(initConfigJSON())
			if err != nil {
				panic(err)
			}
			cf.Close()
		}
	}

	viper.SetConfigType("json")
	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	err := viper.ReadInConfig()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	} else {
		tpURL := viper.GetString("url")
		if tpURL != "" {
			lib.DefaultTPURL = tpURL
		}
		privateKeyFile := viper.GetString("key")
		if privateKeyFile != "" {
			lib.DefaultPrivateKeyFile = privateKeyFile
		}
		listenAddress := viper.GetString("listen")
		if listenAddress != "" {
			lib.DefaultListenAddress = listenAddress
		}
		listenPort := viper.GetInt("port")
		if listenPort != 0 {
			lib.DefaultListenPort = listenPort
		}
		addrs := viper.GetStringSlice("bootstrap")
		if len(addrs) > 0 {
			lib.DefaultBootstrapAddrs = addrs
		}
		seaCfg := viper.GetStringMap("sea")
		if seaCfg != nil {
			storagePath, ok := seaCfg["storagePath"].(string)
			if ok {
				lib.DefaultStoragePath = storagePath
			}
			storageSize, ok := seaCfg["storageSize"].(int64)
			if ok {
				lib.DefaultStorageSize = storageSize
			}
		}
		userCfg := viper.GetStringMap("user")
		if userCfg != nil {
			largeFileSize, ok := userCfg["largeFileSize"].(int64)
			if ok {
				lib.DefaultLargeFileSize = largeFileSize
			}
			dataShards, ok := userCfg["dataShards"].(int)
			if ok {
				lib.DefaultDataShards = dataShards
			}
			parShards, ok := userCfg["parShards"].(int)
			if ok {
				lib.DefaultParShards = parShards
			}
		}
	}
}

// initLogger config logger
func initLogger() {
	lib.Logger = logrus.New()
	lib.Logger.SetFormatter(&logrus.TextFormatter{
		ForceColors: true,
	})
	os.MkdirAll(lib.DefaultLogPath, 0755)
	logFile, err := os.OpenFile(path.Join(lib.DefaultLogPath, "SeaStorage"), os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		logFile, err = os.OpenFile(path.Join(lib.DefaultLogPath, "SeaStorage"), os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			panic(err)
		}
	}
	mw := io.MultiWriter(os.Stdout, logFile)
	lib.Logger.SetOutput(mw)
	if debug {
		lib.Logger.SetLevel(logrus.DebugLevel)
	} else {
		lib.Logger.SetLevel(logrus.WarnLevel)
	}
}

// init P2P bootstrap nodes
func initBootstrapNodes() {
	// Check bootstrap addresses
	for _, addr := range bootstrapAddrs {
		multiaddr, err := ma.NewMultiaddr(addr)
		if err != nil {
			lib.Logger.WithFields(logrus.Fields{
				"peer": addr,
			}).Warn("failed to init peer addr")
		}
		lib.BootstrapAddrs = append(lib.BootstrapAddrs, multiaddr)
	}
}

// init config in JSON format
func initConfigJSON() []byte {
	cfg := make(map[string]interface{})
	cfg["url"] = lib.DefaultTPURL
	cfg["key"] = GetDefaultKeyFile()
	cfg["listen"] = lib.DefaultListenAddress
	cfg["port"] = lib.DefaultListenPort
	cfg["bootstrap"] = lib.DefaultBootstrapAddrs
	cfg["sea"] = map[string]interface{}{
		"storagePath": lib.DefaultStoragePath,
		"storageSize": lib.DefaultStorageSize,
	}
	cfg["user"] = map[string]interface{}{
		"largeFileSize": lib.DefaultLargeFileSize,
		"dataShards":    lib.DefaultDataShards,
		"parShards":     lib.DefaultParShards,
	}
	data, err := json.MarshalIndent(cfg, "", "\t")
	if err != nil {
		panic(err)
	}
	return data
}

// GetDefaultUsername returns the name of current system user.
func GetDefaultUsername() string {
	u, err := user.Current()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	return u.Username
}

// GetDefaultKeyFile returns the default key file named as username
// in the default key path.
func GetDefaultKeyFile() string {
	return path.Join(lib.DefaultKeyPath, GetDefaultUsername()+".priv")
}
