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

package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/manifoldco/promptui"
	"github.com/spf13/cobra"
	tpStorage "gitlab.com/SeaStorage/SeaStorage-TP/storage"
	"gitlab.com/SeaStorage/SeaStorage/lib"
	"gitlab.com/SeaStorage/SeaStorage/user"
)

var userCommands = []string{
	"register",
	"whoami",
	"cd",
	"mkdir",
	"touch",
	"rename",
	"update-info", // TODO
	"update-key",  // TODO
	"rm",
	"mv",
	"share",
	"publish",
	"publish-key",
	"ls",
	"ls-own",
	"ls-user",
	"ls-shared",
	"get",
	"get-own",
	"get-shared",
	"download",
	"download-shared",
	"exit",
}

var (
	errMissingOperand = errors.New("missing operand")
	errInvalidPath    = errors.New("invalid path")
)

// userCmd represents the user command
var userCmd = &cobra.Command{
	Use:   "user",
	Short: "SeaStorage User Command Client",
	Long: `SeaStorage User Command Client is a platform support
communicating with the transaction processor.`,
	Run: func(cmd *cobra.Command, args []string) {
		if name == "" {
			fmt.Println(errors.New("the name of user/sea is required"))
			os.Exit(0)
		}
		cli, err := user.NewUserClient(name, lib.PrivateKeyFile, lib.BootstrapAddrs)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		var response map[string]interface{}
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
					return fmt.Errorf("command not found: %v", commands[0])
				},
			}
			response = nil
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
				err = cli.UserRegister()
				if err != nil {
					fmt.Println(err)
				} else {
					fmt.Println("User register success.")
				}
				continue
			} else if cli.User == nil {
				fmt.Println("need register firstly")
				continue
			} else {
				err = cli.Sync()
				if err != nil {
					fmt.Println(err)
					continue
				}
			}
			switch commands[0] {
			case "whoami":
				cli.ClientFramework.Whoami()
			case "cd":
				if len(commands) == 1 {
					err = cli.ChangePWD("/")
				} else if len(commands) > 2 {
					err = errInvalidPath
				} else {
					err = cli.ChangePWD(commands[1])
				}
				if err != nil {
					fmt.Println(err)
				}
			case "ls":
				var iNodes []tpStorage.INodeInfo
				if len(commands) == 1 {
					iNodes, err = cli.ListDirectory(cli.PWD)
				} else if len(commands) > 2 {
					err = errInvalidPath
				} else {
					iNodes, err = cli.ListDirectory(commands[1])
				}
				if err != nil {
					fmt.Println(err)
				} else {
					printINodeInfo(iNodes)
				}
			case "ls-own":
				var iNodes []tpStorage.INodeInfo
				if len(commands) == 1 {
					iNodes, err = cli.ListSharedDirectory(cli.PWD)
				} else if len(commands) > 2 {
					err = errInvalidPath
				} else {
					iNodes, err = cli.ListSharedDirectory(commands[1])
				}
				if err != nil {
					fmt.Println(err)
				} else {
					printINodeInfo(iNodes)
				}
			case "ls-user":
				if len(commands) == 1 {
					err := cli.ListUsersShared(false)
					if err != nil {
						fmt.Println(err)
						return
					}
					for addr := range cli.QueryCache {
						fmt.Println("Address: ", addr)
					}
					return
				} else if len(commands) == 2 {
					if commands[1] == "next" {
						err := cli.ListUsersShared(true)
						if err != nil {
							fmt.Println(err)
							return
						}
						for addr := range cli.QueryCache {
							fmt.Println("Address: ", addr)
						}
					}
				} else {
					fmt.Println(errMissingOperand)
				}
			case "ls-shared":
				if len(commands) < 3 {
					fmt.Println(errMissingOperand)
				} else if len(commands) > 3 {
					fmt.Println(errInvalidPath)
				} else {
					infos, err := cli.ListOtherSharedDirectory(commands[1], commands[2])
					if err != nil {
						fmt.Println(err)
						return
					}
					printINodeInfo(infos)
				}
			case "mkdir":
				if len(commands) < 2 {
					fmt.Println(errMissingOperand)
				} else if len(commands) > 2 {
					fmt.Println(errInvalidPath)
				} else {
					response, err = cli.CreateDirectory(commands[1])
					if err != nil {
						fmt.Println(err)
					} else {
						lib.PrintResponse(response)
					}
				}
			case "touch":
				if len(commands) < 3 {
					fmt.Println(errMissingOperand)
				} else if len(commands) > 3 {
					fmt.Println(errInvalidPath)
				} else {
					// TODO: Select Sea To Store File & Select data shards
					response, err = cli.CreateFile(commands[1], commands[2], lib.DefaultDataShards, lib.DefaultParShards)
					if err != nil {
						fmt.Println(err)
					} else {
						lib.PrintResponse(response)
					}
				}
			case "rename":
				if len(commands) < 3 {
					fmt.Println(errMissingOperand)
				} else if len(commands) > 3 {
					fmt.Println(errInvalidPath)
				} else {
					response, err = cli.Rename(commands[1], commands[2])
					if err != nil {
						fmt.Println(err)
					} else {
						lib.PrintResponse(response)
					}
				}
			case "rm":
				if len(commands) < 2 {
					fmt.Println(errMissingOperand)
					continue
				} else if len(commands) > 2 {
					fmt.Println(errInvalidPath)
					continue
				}
				iNode, err := cli.GetINode(commands[1])
				if err != nil {
					fmt.Println(err)
					continue
				}
				switch iNode.(type) {
				case *tpStorage.Directory:
					confirmPrompt := &promptui.Prompt{
						Label:     fmt.Sprintf("Remove directory %s? [y/N]", commands[1]),
						Templates: commandTemplates,
						Default:   "n",
					}
					conf, err := confirmPrompt.Run()
					if err != nil {
						fmt.Println(err)
						continue
					}
					switch conf {
					case "y", "Y":
						response, err = cli.DeleteDirectory(commands[1])
					default:
						continue
					}
				case *tpStorage.File:
					confirmPrompt := &promptui.Prompt{
						Label:     fmt.Sprintf("Remove file %s? [y/N]", commands[1]),
						Templates: commandTemplates,
						Default:   "n",
					}
					conf, err := confirmPrompt.Run()
					if err != nil {
						fmt.Println(err)
						continue
					}
					switch conf {
					case "y", "Y":
						response, err = cli.DeleteFile(commands[1])
					default:
						continue
					}
				}
				if err != nil {
					fmt.Println(err)
				} else {
					lib.PrintResponse(response)
				}
			case "mv":
				if len(commands) < 3 {
					fmt.Println(errMissingOperand)
				} else if len(commands) > 3 {
					fmt.Println(errInvalidPath)
				} else {
					response, err := cli.Move(commands[1], commands[2])
					if err != nil {
						fmt.Println(err)
					} else {
						lib.PrintResponse(response)
					}
				}
			case "get":
				if len(commands) < 2 {
					fmt.Println(errMissingOperand)
				} else if len(commands) > 2 {
					fmt.Println(errInvalidPath)
				} else {
					iNode, err := cli.GetINode(commands[1])
					if err != nil {
						fmt.Println(err)
					} else {
						printINode(iNode)
					}
				}
			case "get-own":
				if len(commands) < 2 {
					fmt.Println(errMissingOperand)
				} else if len(commands) > 2 {
					fmt.Println(errInvalidPath)
				} else {
					iNode, err := cli.GetSharedINode(commands[1])
					if err != nil {
						fmt.Println(err)
					} else {
						printINode(iNode)
					}
				}
			case "get-shared":
				if len(commands) < 3 {
					fmt.Println(errMissingOperand)
				} else if len(commands) > 3 {
					fmt.Println(errInvalidPath)
				} else {
					iNode, err := cli.GetOtherSharedINode(commands[1], commands[2])
					if err != nil {
						fmt.Println(err)
					} else {
						printINode(iNode)
					}
				}
			case "download":
				if len(commands) < 3 {
					fmt.Println(errMissingOperand)
				} else if len(commands) > 3 {
					fmt.Println(errInvalidPath)
				} else {
					cli.DownloadFiles(commands[1], commands[2])
				}
			case "download-shared":
				if len(commands) < 3 {
					fmt.Println(errMissingOperand)
				} else if len(commands) > 4 {
					fmt.Println(errInvalidPath)
				} else {
					owner := ""
					if len(commands) == 4 {
						owner = commands[3]
					}
					cli.DownloadSharedFiles(commands[1], commands[2], owner)
				}
			case "publish-key":
				if len(commands) < 2 {
					fmt.Println(errMissingOperand)
				} else if len(commands) > 2 {
					fmt.Println(errInvalidPath)
				} else {
					response, err = cli.PublishKey(commands[1])
					if err != nil {
						fmt.Println(err)
					} else {
						lib.PrintResponse(response)
					}
				}
			case "share":
				if len(commands) < 3 {
					fmt.Println(errMissingOperand)
				} else if len(commands) > 3 {
					fmt.Println(errInvalidPath)
				} else {
					keys, response, err := cli.ShareFiles(commands[1], commands[2])
					if err != nil {
						fmt.Println(err)
					} else {
						printKeys(keys)
						lib.PrintResponse(response)
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

// printINodeInfo display the informations of iNode.
func printINodeInfo(iNodes []tpStorage.INodeInfo) {
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
	err := w.Flush()
	if err != nil {
		fmt.Println(err)
	}
}

// printINode display the information of iNode.
func printINode(iNode tpStorage.INode) {
	data, err := json.MarshalIndent(iNode, "", "\t")
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println(string(data))
	}
}

// printKeys display the key and its index.
func printKeys(keys map[string]string) {
	data, err := json.Marshal(keys)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println(string(data))
	}
}
