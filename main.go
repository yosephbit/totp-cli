package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func main() {
	var service string
	var timestamp int64

	viper.SetConfigFile("config.yaml") // Set the configuration file
	viper.ReadInConfig()               // Read the configuration file

	generateCmd := &cobra.Command{
		Use:   "generate [service]",
		Short: "Generate a TOTP code",
		Args:  cobra.ExactArgs(1), // Expect exactly one argument (service)
		Run: func(cmd *cobra.Command, args []string) {
			// Use the current time if timestamp is not specified
			if timestamp == 0 {
				timestamp = time.Now().Unix()
			}
			service = args[0]
			secretKey := viper.GetString(service) // Get the secret key from the configuration file
			if secretKey == "" {
				fmt.Printf("Service '%s' not found in the configuration file.\n", service)
				os.Exit(1)
			}
			code := generateTOTP(secretKey, timestamp)
			fmt.Printf("%06d\n", code)
		},
	}

	generateCmd.Flags().Int64VarP(&timestamp, "timestamp", "t", 0, "The timestamp (in seconds)")

	generateCmd.Execute()
}

func generateTOTP(secretKey string, timestamp int64) uint32 {

	// The base32 encoded secret key string is decoded to a byte slice
	base32Decoder := base32.StdEncoding.WithPadding(base32.NoPadding)
	secretKey = strings.ToUpper(strings.TrimSpace(secretKey)) // preprocess
	secretBytes, _ := base32Decoder.DecodeString(secretKey)   // decode

	// The truncated timestamp / 30 is converted to an 8-byte big-endian
	// unsigned integer slice
	timeBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timeBytes, uint64(timestamp)/30)

	// The timestamp bytes are concatenated with the decoded secret key
	// bytes. Then a 20-byte SHA-1 hash is calculated from the byte slice
	hash := hmac.New(sha1.New, secretBytes)
	hash.Write(timeBytes) // Concat the timestamp byte slice
	h := hash.Sum(nil)    // Calculate 20-byte SHA-1 digest

	// AND the SHA-1 with 0x0F (15) to get a single-digit offset
	offset := h[len(h)-1] & 0x0F

	// Truncate the SHA-1 by the offset and convert it into a 32-bit
	// unsigned int. AND the 32-bit int with 0x7FFFFFFF (2147483647)
	// to get a 31-bit unsigned int.
	truncatedHash := binary.BigEndian.Uint32(h[offset:]) & 0x7FFFFFFF

	// Take modulo 1_000_000 to get a 6-digit code
	return truncatedHash % 1_000_000
}
