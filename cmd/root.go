// Copyright © 2019 NAME HERE <EMAIL ADDRESS>
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
	"fmt"
	"gitlab.com/SeaStorage/SeaStorage/lib"
	"os"
	"os/user"
	"path"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile string
	name    string
	keyFile string
	debug   bool
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   lib.FamilyName,
	Short: "Decentralized cloud storage application",
	Long: `SeaStorage is a decentralized cloud storage application.
This application is a tool for store files on a P2P
network based on hyperledger sawtooth.`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	//	Run: func(cmd *cobra.Command, args []string) { },
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
	cobra.OnInitialize(initConfig)
	logrus.SetFormatter(&logrus.TextFormatter{})
	logrus.SetOutput(os.Stdout)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file")
	rootCmd.PersistentFlags().StringVarP(&name, "name", "n", GetDefaultUserName(), "the name of user/sea")
	rootCmd.PersistentFlags().StringVarP(&lib.TPURL, "url", "u", lib.DefaultTPURL, "the sawtooth rest api")
	rootCmd.PersistentFlags().StringVarP(&keyFile, "key", "k", GetDefaultKeyFile(), "the private key file for identity")
	rootCmd.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "debug version")
	rootCmd.PersistentFlags().StringVarP(&lib.ListenAddress, "listen", "l", lib.DefaultListenAddress, "the listen address for p2p network")
	rootCmd.PersistentFlags().IntVarP(&lib.ListenPort, "port", "p", lib.DefaultListenPort, "the listen port for p2p network")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	u, err := user.Current()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// TODO: Init Config file
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Search config in home directory with name ".SeaStorage" (without extension).
		viper.AddConfigPath(path.Join(u.HomeDir, ".SeaStorage"))
		viper.SetConfigName("config")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}

	if debug {
		logrus.SetLevel(logrus.DebugLevel)
	} else {
		logrus.SetLevel(logrus.WarnLevel)
	}
}

func GetDefaultUserName() string {
	u, err := user.Current()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	return u.Username
}

func GetDefaultKeyFile() string {
	u, err := user.Current()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	return path.Join(u.HomeDir, ".SeaStorage", "keys", u.Username+".priv")
}
