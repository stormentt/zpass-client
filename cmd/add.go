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
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stormentt/zpass-client/api/passwords"
	"github.com/stormentt/zpass-client/index"
	"github.com/stormentt/zpass-client/keyvault"
	"github.com/stormentt/zpass-lib/random"
	"github.com/stormentt/zpass-lib/util"
)

// addCmd represents the add command
var addCmd = &cobra.Command{
	Use:   "add",
	Short: "Add something to your zpass user",
	Long:  `zpass add password`,
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
			addType := args[0]
			switch addType {
			case "password":
				pwName := viper.GetString("pw-name")
				if pwName == "" {
					input, _ := util.AskPass("Password Name: ")
					pwName = string(input)
				}

				selector := ""
				if viper.GetBool("generate") == true {
					password, _ := random.AlphaNum(viper.GetInt("pw-length"))
					selector, _ = passwords.Store(password)
				} else {
					password, _ := util.AskPass("New Password: ")
					selector, _ = passwords.Store(string(password))
				}
				log.WithFields(log.Fields{
					"name":     pwName,
					"selector": selector,
				}).Info("Adding pw")
				index.Add(pwName, selector)

				index.Save(viper.GetString("index-path"))
			}
		}
	},
}

func init() {
	RootCmd.AddCommand(addCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// addCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	addCmd.Flags().BoolP("generate", "g", false, "Whether or not to generate the password")
	viper.BindPFlag("generate", addCmd.Flags().Lookup("generate"))

	addCmd.Flags().IntP("length", "l", 32, "Length of the generated password")
	viper.BindPFlag("pw-length", addCmd.Flags().Lookup("length"))

	addCmd.Flags().StringP("name", "n", "", "Name of the password to add")
	viper.BindPFlag("pw-name", addCmd.Flags().Lookup("name"))
}
