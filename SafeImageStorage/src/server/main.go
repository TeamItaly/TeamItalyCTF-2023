package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	log "github.com/sirupsen/logrus"
	"hash/crc32"
	"image"
	"image/png"
	"io"
	"net/http"
	"nhooyr.io/websocket"
	"os"
	"path/filepath"
)

const (
	imagesPath    = "/images"
	serverKeyPath = "/data/server.key"
	protoMagic    = 0x64657667 // devg
)

var serverKey []byte

type encCipher uint8

const (
	encCipherAesCbc encCipher = 0
	encCipherAesCtr encCipher = 1
	encCipherAesCfb encCipher = 2
	encCipherAesEcb encCipher = 3
)

func handleClient(c *websocket.Conn) error {
	defer func() {
		if err := recover(); err != nil {
			log.Errorf("panicked while handling client: %v", err)
		}
	}()

	for {
		mt, data, err := c.Read(context.Background())
		if websocket.CloseStatus(err) != -1 {
			return nil
		} else if err != nil {
			return fmt.Errorf("failed creating reader: %w", err)
		} else if mt != websocket.MessageBinary {
			return fmt.Errorf("invalid message type")
		}

		r := bytes.NewReader(data)

		// magic
		var magic uint32
		if err := binary.Read(r, binary.BigEndian, &magic); err != nil {
			return err
		}

		// options
		var options uint8
		if err := binary.Read(r, binary.BigEndian, &options); err != nil {
			return err
		}

		// client key
		clientKey := make([]byte, 16)
		if _, err := io.ReadFull(r, clientKey); err != nil {
			return err
		}

		// name length
		var nameLen uint16
		if err := binary.Read(r, binary.BigEndian, &nameLen); err != nil {
			return err
		}

		// name
		name := make([]byte, nameLen)
		if _, err := io.ReadFull(r, name); err != nil {
			return err
		}

		// read checksum
		var reqChecksum uint32
		if err := binary.Read(r, binary.BigEndian, &reqChecksum); err != nil {
			return err
		}

		// verify checksum
		if reqChecksum != crc32.ChecksumIEEE(data[:len(data)-4]) {
			return fmt.Errorf("invalid request")
		}

		if magic != protoMagic {
			return fmt.Errorf("invalid request")
		} else if options < uint8(encCipherAesCbc) || options > uint8(encCipherAesEcb) {
			return fmt.Errorf("invalid request")
		}

		imagePath := filepath.Join(imagesPath, filepath.Clean("/"+string(name)))
		imageFile, err := os.Open(imagePath)
		if err != nil {
			return fmt.Errorf("failed opening image: %w", err)
		}

		var encryptedImageBuf bytes.Buffer
		if err := encryptImage(imageFile, &encryptedImageBuf, encCipher(options), serverKey, clientKey); err != nil {
			_ = imageFile.Close()
			return err
		}

		_ = imageFile.Close()

		w, err := c.Writer(context.Background(), websocket.MessageBinary)
		if err != nil {
			return fmt.Errorf("failed creating writer: %w", err)
		}

		encryptedImage := encryptedImageBuf.Bytes()
		if err := binary.Write(w, binary.BigEndian, uint32(len(encryptedImage))); err != nil {
			_ = w.Close()
			return err
		}

		if _, err := w.Write(encryptedImage); err != nil {
			_ = w.Close()
			return err
		}

		_ = w.Close()
	}
}

func encryptImage(reader io.Reader, writer io.Writer, ec encCipher, serverKey, clientKey []byte) error {
	key := func() []byte { h := hmac.New(sha256.New, serverKey); _, _ = h.Write(clientKey); return h.Sum(nil) }()

	img, _, err := image.Decode(reader)
	if err != nil {
		return fmt.Errorf("failed decoding image: %w", err)
	}

	var pixels []uint8
	switch img := img.(type) {
	case *image.NRGBA:
		pixels = img.Pix
	case *image.RGBA:
		pixels = img.Pix
	default:
		return fmt.Errorf("unsupported image format")
	}

	bc, err := aes.NewCipher(key[:aes.BlockSize])
	if err != nil {
		return fmt.Errorf("failed initializing cipher: %w", err)
	}

	switch ec {
	case encCipherAesEcb:
		for i := 0; i < len(pixels); i += aes.BlockSize {
			bc.Encrypt(pixels[i:i+aes.BlockSize], pixels[i:i+aes.BlockSize])
		}
	case encCipherAesCbc:
		sm := cipher.NewCBCEncrypter(bc, key[aes.BlockSize:aes.BlockSize*2])
		sm.CryptBlocks(pixels, pixels)
	case encCipherAesCtr:
		sm := cipher.NewCTR(bc, key[aes.BlockSize:aes.BlockSize*2])
		sm.XORKeyStream(pixels, pixels)
	case encCipherAesCfb:
		sm := cipher.NewCFBEncrypter(bc, key[aes.BlockSize:aes.BlockSize*2])
		sm.XORKeyStream(pixels, pixels)
	default:
		return fmt.Errorf("unsupported image format")
	}

	if err := png.Encode(writer, img); err != nil {
		return fmt.Errorf("failed encoding image: %w", err)
	}

	return nil
}

func main() {
	var err error
	if serverKey, err = os.ReadFile(serverKeyPath); os.IsNotExist(err) {
		serverKey = make([]byte, aes.BlockSize)
		if _, err = rand.Read(serverKey); err != nil {
			log.WithError(err).Fatal("failed generating random server key")
		} else if err = os.WriteFile(serverKeyPath, serverKey, 0600); err != nil {
			log.WithError(err).Fatal("failed saving server key")
		}
	} else if err != nil {
		log.WithError(err).Fatal("failed reading server key")
	}

	log.Infof("server key is %s", hex.EncodeToString(serverKey))

	fileServer := http.FileServer(http.Dir("/var/www/html"))

	http.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != "GET" {
			writer.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		if request.Header.Get("Upgrade") == "websocket" {
			c, err := websocket.Accept(writer, request, &websocket.AcceptOptions{})
			if err != nil {
				writer.WriteHeader(http.StatusInternalServerError)
				return
			}

			if err := handleClient(c); err != nil {
				log.WithError(err).Error("failed handling client")
				_ = c.Close(websocket.StatusInternalError, "")
			} else {
				_ = c.Close(websocket.StatusNormalClosure, "")
			}
			return
		}

		fileServer.ServeHTTP(writer, request)
	})

	if err := http.ListenAndServe("0.0.0.0:1337", http.DefaultServeMux); err != nil {
		log.WithError(err).Fatal("failed listening")
	}
}
