package main

import (
	"bytes"
	"testing"

	"golang.org/x/crypto/chacha20"
)

var (
	testKey   = []byte(`DEADBEEFDEADBEEFDEADBEEFDEADBEEF`)
	testNonce = make([]byte, chacha20.NonceSize)
)

var testBytes = [][]byte{
	[]byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."),
	[]byte(`良い１日を`),
	[]byte(`42`),
	[]byte(`what am I doing here`),
	[]byte(`тестирование`),
	[]byte(`They will not calm down, Daniel Jackson, they will in fact calm up.`),
	[]byte(``),
}

func TestEncryptDecryptCryptor(t *testing.T) {
	cryptor := NewCryptor(WithKey(testKey), WithNonce(testNonce))

	for _, test := range testBytes {
		// encrypt
		var ciphertextOut bytes.Buffer
		if err := cryptor.StreamCrypt(bytes.NewReader(test), &ciphertextOut); err != nil {
			t.Fatal("encryption error", "test", test, "error", err)
		}

		if bytes.Equal(test, ciphertextOut.Bytes()) && !bytes.Equal(test, []byte(``)) {
			t.Fatal("encryption error", "test", test, "cipher text", ciphertextOut.String())
		}

		// decrypt
		var plaintextOut bytes.Buffer
		// strings.NewReader(testStrs[i].cipherText.String())
		if err := cryptor.StreamCrypt(&ciphertextOut, &plaintextOut); err != nil {
			t.Fatal("decryption error", "test", test, "error", err)
		}

		want, got := test, plaintextOut.Bytes()
		if !bytes.Equal(want, got) {
			t.Fatal("wanted", want, "got", got)
		}
	}
}

// TODO: filepath.WalkDir seems much higher to test than fs.WalkDir
