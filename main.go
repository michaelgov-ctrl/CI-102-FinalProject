package main

import (
	"flag"
	"log"
	"os"
	"strings"

	cryptor "github.com/michaelgov-ctrl/CI-102-SecurityProject/pkg"
)

func main() {
	var targetDirectories, key string
	flag.StringVar(&targetDirectories, "target_directories", "", "[required] Comma-separated list of directories to encrypt")
	flag.StringVar(&key, "key", "", "Key to use for encryption/decryption")

	var workerCount int
	flag.IntVar(&workerCount, "worker_count", 5, "Number of workers to encrypt/decrpyt with")

	var encrypt, decrypt bool
	flag.BoolVar(&encrypt, "encrypt", false, "Pass to encrypt data")
	flag.BoolVar(&decrypt, "decrypt", false, "Pass to decrypt data")

	flag.Parse()

	dirs := strings.Split(targetDirectories, ", ")

	if (targetDirectories == "" || len(dirs) == 0) || encrypt == decrypt {
		flag.Usage()
		os.Exit(1)
	}

	opts := []cryptor.Option{
		cryptor.WithWorkerCount(workerCount),
	}

	state := cryptor.Decrypting
	if encrypt {
		state = cryptor.Encrypting
	}
	opts = append(opts, cryptor.WithEncryptionState(state))

	if key != "" {
		opts = append(opts, cryptor.WithKey([]byte(key)))
	}

	cryptor := cryptor.NewCryptor(opts...)

	cryptor.EnumerateDirectories(dirs)

	log.Printf("%s files with chacha20 stream cipher\nkey: %s\n", cryptor.EncryptingOrDecrypting, cryptor.Key)
	err := cryptor.ManageEncryption()
	if err != nil {
		log.Fatal(err)
	}
}
