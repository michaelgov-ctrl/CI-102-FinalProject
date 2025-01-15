package main

import (
	"flag"
	"log"
	"os"
	"strings"
)

func main() {
	var targetDirectories string
	flag.StringVar(&targetDirectories, "target_directories", "", "[required] Comma-separated list of directories to encrypt")

	var workerCount int
	flag.IntVar(&workerCount, "worker_count", 5, "Number of workers to encrypt/decrpyt with")

	var encrypt bool
	flag.BoolVar(&encrypt, "encrypt", false, "Pass to encrypt data")

	flag.Parse()

	dirs := strings.Split(targetDirectories, ", ")
	//do nothing unless explicitly requested
	if targetDirectories == "" || len(dirs) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	cryptor := NewCryptor(WithWorkerCount(workerCount), WithEncryption(encrypt))

	cryptor.EnumerateDirectories(dirs)

	log.Printf("%s files with chacha20 stream cipher\nkey: %s\n", cryptor.EncryptingOrDecrypting, cryptor.Key)
	err := cryptor.ListenAndManageEncryption()
	if err != nil {
		log.Fatal(err)
	}
}
