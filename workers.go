package main

import (
	"log"
)

func (e *Encryptor) NewWorker() {
	defer e.wg.Done()
	for path := range e.JobChan {
		err := e.Encrypt(path)
		log.Printf("target: %s, status: %v\n", path, err)
	}
}
