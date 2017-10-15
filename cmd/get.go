// Copyright © 2017 NAME HERE <EMAIL ADDRESS>
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
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stormentt/zpass-client/api/passwords"
	"github.com/stormentt/zpass-client/index"
	"github.com/stormentt/zpass-client/keyvault"
)

// getCmd represents the get command
var getCmd = &cobra.Command{
	Use:   "get",
	Short: "Get something from the server",
	Long:  `zpass get password [password name]`,
	Run: func(cmd *cobra.Command, args []string) {
		err := keyvault.Open(viper.GetString("keyvault-path"))
		if err != nil {
			log.Error(err)
			return
		}

		err = index.Open(viper.GetString("index-path"))
		if err != nil {
			return
		}

		if len(args) > 0 {
			getType := args[0]
			switch getType {
			case "password":
				name := viper.GetString("pw-name")
				selector := viper.GetString("pw-selector")
				password := ""
				if name != "" {
					selector, _ := index.Get(name)
					password = passwords.Get(selector)
				} else if selector != "" {
					password = passwords.Get(selector)
				}
				fmt.Println(password)
			}
		}
	},
}

func init() {
	RootCmd.AddCommand(getCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// getCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	getCmd.Flags().StringP("name", "n", "", "Password name to retrieve")
	viper.BindPFlag("pw-name", getCmd.Flags().Lookup("name"))

	getCmd.Flags().StringP("selector", "s", "", "Password selector to retrieve")
	viper.BindPFlag("pw-selector", getCmd.Flags().Lookup("selector"))
}
