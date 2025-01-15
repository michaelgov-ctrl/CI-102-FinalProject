package main

import (
	"log"
	"strings"
	"sync"
)

func (c *Cryptor) NewWorker(wg *sync.WaitGroup) {
	defer wg.Done()
	for path := range c.JobChan {
		var (
			status      = "success"
			suffixCheck = strings.HasSuffix(path, EncryptedExtension)
		)

		if c.EncryptingOrDecrypting == Encrypting && suffixCheck {
			log.Printf("target: %s, already encrypted\n", path)
			continue
		}

		if c.EncryptingOrDecrypting == Decrypting && !suffixCheck {
			log.Printf("target: %s, not encrypted\n", path)
			continue
		}

		if err := c.CryptFunc(path, c.StreamCrypt); err != nil {
			status = err.Error()
		}

		log.Printf("target: %s, status: %v\n", path, status)
	}
}
