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
	"errors"
	"fmt"
	"github.com/manifoldco/promptui"
	"github.com/spf13/cobra"
	"gitlab.com/SeaStorage/SeaStorage-TP/storage"
	"gitlab.com/SeaStorage/SeaStorage/user"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
)

var userCommands = []string{
	"register",
	"whoami",
	"cd",
	"mkdir",
	"touch",
	"rename",
	"update-info",
	"update-key",
	"rm",
	"share",
	"public",
	"public-key",
	"ls",
	"get",
	"download",
	"exit",
}

// userCmd represents the user command
var userCmd = &cobra.Command{
	Use:   "user",
	Short: "SeaStorage User Command Client",
	Long:  `SeaStorage User Command Client is a platform support
			communicating with the transaction processor.`,
	Run: func(cmd *cobra.Command, args []string) {
		if name == "" {
			fmt.Println(errors.New("the name of user/sea is required"))
			os.Exit(0)
		}
		cli, err := user.NewUserClient(name, url, keyFile)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		for {
			prompt := promptui.Prompt{
				Label:     cli.PWD + " ",
				Templates: commandTemplates,
				Validate: func(s string) error {
					commands := strings.Fields(s)
					if len(commands) == 0 {
						return nil
					}
					for _, c := range userCommands {
						if c == commands[0] {
							return nil
						}
					}
					return errors.New(fmt.Sprintf("command not found: %v", commands[0]))
				},
			}
			err = nil
			input, err := prompt.Run()
			if err != nil {
				fmt.Println(err)
				return
			}
			commands := strings.Fields(input)
			if commands[0] == "exit" {
				return
			} else if commands[0] == "register" {
				if cli.User != nil {
					fmt.Println("Already register.")
					continue
				}
				err = cli.Register()
				if err != nil {
					fmt.Println(err)
				} else {
					fmt.Println("User register success.")
				}
				continue
			} else if cli.User == nil {
				fmt.Println("need register firstly")
				continue
			}
			switch commands[0] {
			case "whoami":
				cli.ClientFramework.Whoami()
			case "cd":
				if len(commands) == 1 {
					err = cli.ChangePWD("/")
				} else if len(commands) > 2 {
					err = errors.New("invalid path")
				} else {
					err = cli.ChangePWD(commands[1])
				}
				if err != nil {
					fmt.Println(err)
				}
			case "ls":
				var iNodes []storage.INodeInfo
				if len(commands) == 1 {
					iNodes, err = cli.ListDirectory(cli.PWD)
				} else if len(commands) > 2 {
					err = errors.New("invalid path")
				} else {
					iNodes, err = cli.ListDirectory(commands[1])
				}
				if err != nil {
					fmt.Println(err)
				} else {
					fmt.Println("Total", len(iNodes), "items.")
					w := new(tabwriter.Writer)
					w.Init(os.Stdout, 0, 8, 2, '\t', 0)
					var category string
					for _, iNode := range iNodes {
						if iNode.IsDir {
							category = "Dir"
						} else {
							category = "File"
						}
						_, err := fmt.Fprintln(w, strings.Join([]string{
							category,
							iNode.Name,
							strconv.Itoa(int(iNode.Size)),
						}, "\t"))
						if err != nil {
							fmt.Println(err)
							break
						}
					}
					err = w.Flush()
					if err != nil {
						fmt.Println(err)
					}
				}
			case "mkdir":
				if len(commands) < 2 {
					fmt.Println(errors.New("missing operand"))
				} else if len(commands) > 2 {
					fmt.Println(errors.New("invalid path"))
				} else {
					response, err := cli.CreateDirectory(commands[1])
					if err != nil {
						fmt.Println(err)
					} else {
						fmt.Println(response)
					}
				}
			case "touch":
				if len(commands) < 2 {
					fmt.Println(errors.New("missing operand"))
				} else if len(commands) > 2 {
					fmt.Println(errors.New("invalid path"))
				} else {
					response, err := cli.CreateFile(commands[1], commands[2])
					if err != nil {
						fmt.Println(err)
					} else {
						fmt.Println(response)
					}
				}
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(userCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// userCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// userCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
