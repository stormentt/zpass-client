// Copyright © 2017 Tanner Storment
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

package cmd

import (
	"fmt"
	"os"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"zpass-lib/crypt"
)

var cfgFile string

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "zpass-client",
	Short: "Client program for the zpass storage server",
	Long: `zpass-client is used to connect to a running zpass server.
	
	The client looks for its config file in ./zpass-client.json
	
	Config file options:
	keyvault-path
		Path to the zpass keyvault. This is where zpass will store your password encryption key & device authentication information.
	server 
		The remote server to connect to
	port 
		The remote port to connect to
	`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	//	Run: func(cmd *cobra.Command, args []string) { },
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	cobra.OnInitialize(setDefaultConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.
	RootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.zpass-client.yaml)")
	RootCmd.PersistentFlags().String("server", "localhost", "Server to connect to")
	viper.BindPFlag("server", RootCmd.PersistentFlags().Lookup("server"))
	RootCmd.PersistentFlags().Int("port", 8080, "Port to connect to")
	viper.BindPFlag("port", RootCmd.PersistentFlags().Lookup("port"))

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	RootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// Search config in home directory with name ".zpass-client" (without extension).
		viper.AddConfigPath(home)
		viper.AddConfigPath(".")
		viper.SetConfigName("zpass-client")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}

func setDefaultConfig() {
	viper.SetDefault("Hasher", "sha512")
	viper.SetDefault("Crypter", "chacha20poly1305")

	crypt.ConfigHasher = viper.GetString("Hasher")
	crypt.ConfigCrypter = viper.GetString("Crypter")
}
