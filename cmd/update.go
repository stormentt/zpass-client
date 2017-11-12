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
	"github.com/stormentt/zpass-client/keyvault"
	"github.com/stormentt/zpass-lib/util"
)

// updateCmd represents the update command
var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Updates something in the server",
	Long:  `zpass update password [selector]`,
	Run: func(cmd *cobra.Command, args []string) {
		err := keyvault.Open(viper.GetString("keyvault-path"))
		if err != nil {
			log.Error(err)
			return
		}

		if len(args) > 1 {
			updateType := args[0]
			switch updateType {
			case "password":
				selector := args[1]
				password, _ := util.AskPass("New Password: ")
				passwords.Update(selector, string(password))
			}
		}
	},
}

func init() {
	RootCmd.AddCommand(updateCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// updateCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// updateCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
