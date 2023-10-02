//go:build js

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
	"hash/crc32"
	"image"
	"image/png"
	"io"
	"log"
	"nhooyr.io/websocket"
	"strings"
	"syscall/js"
	"time"
)

const protoMagic = 0x64657667 // devg

var ws *websocket.Conn

func requestImage(name string, clientKey []byte) ([]byte, error) {
	var reqBuffer bytes.Buffer

	// magic bytes
	_ = binary.Write(&reqBuffer, binary.BigEndian, uint32(protoMagic))

	// options
	_ = binary.Write(&reqBuffer, binary.BigEndian, uint8(0))

	// client key
	_, _ = reqBuffer.Write(clientKey)

	// name length
	_ = binary.Write(&reqBuffer, binary.BigEndian, uint16(len(name)))

	// name
	_, _ = reqBuffer.Write([]byte(name))

	// checksum
	checksum := crc32.ChecksumIEEE(reqBuffer.Bytes())
	_ = binary.Write(&reqBuffer, binary.BigEndian, checksum)

	if err := ws.Write(context.Background(), websocket.MessageBinary, reqBuffer.Bytes()); err != nil {
		return nil, fmt.Errorf("failed writing request: %w", err)
	}

	mt, data, err := ws.Read(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed reading response: %w", err)
	} else if mt != websocket.MessageBinary {
		return nil, fmt.Errorf("invalid message type")
	}

	imageLen := binary.BigEndian.Uint32(data)
	if int(imageLen) > len(data)-4 {
		return nil, fmt.Errorf("not enough data to read")
	}

	return data[4 : 4+imageLen], nil
}

func decryptImage(reader io.Reader, writer io.Writer, clientKey, serverKey []byte) error {
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

	// decrypt image
	key := func() []byte { h := hmac.New(sha256.New, serverKey); _, _ = h.Write(clientKey); return h.Sum(nil) }()

	bc, err := aes.NewCipher(key[:aes.BlockSize])
	if err != nil {
		return fmt.Errorf("failed initializing cipher: %w", err)
	}

	sm := cipher.NewCBCDecrypter(bc, key[aes.BlockSize:aes.BlockSize*2])
	sm.CryptBlocks(pixels, pixels)

	if err := png.Encode(writer, img); err != nil {
		return fmt.Errorf("failed encoding image: %w", err)
	}

	return nil
}

type imageRequest struct {
	name      string
	serverKey []byte
	resp      chan imageResponse
}

type imageResponse struct {
	data []byte
	err  error
}

func main() {
	loc := js.Global().Get("location").Get("origin").String()
	if !strings.HasPrefix(loc, "http") {
		println("invalid location")
		return
	}

	loc = strings.Replace(loc, "http", "ws", 1)

	var err error
	ws, _, err = websocket.Dial(context.Background(), loc, &websocket.DialOptions{})
	if err != nil {
		log.Fatalf("failed connecting websocket: %v", err)
	}

	ws.SetReadLimit(10 * 1024 * 1024) // 10MiB

	req := make(chan imageRequest)

	go func() {
		for {
			select {
			case r := <-req:
				// create random client key
				clientKey := make([]byte, 16)
				_, _ = rand.Read(clientKey)

				// get image from server
				imageDataEnc, err := requestImage(r.name, clientKey)
				if err != nil {
					r.resp <- imageResponse{nil, err}
					continue
				}

				// decrypt image
				var imageDataBuf bytes.Buffer
				if err := decryptImage(bytes.NewReader(imageDataEnc), &imageDataBuf, clientKey, r.serverKey); err != nil {
					r.resp <- imageResponse{nil, err}
					continue
				}

				r.resp <- imageResponse{imageDataBuf.Bytes(), nil}
			}
		}
	}()

	js.Global().Set("requestImage", js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) != 3 {
			return "invalid number of arguments"
		}

		name, serverKeyHex, cb := args[0].String(), args[1].String(), args[2]

		serverKey, err := hex.DecodeString(serverKeyHex)
		if err != nil {
			cb.Invoke(nil, "invalid server key")
			return js.Undefined()
		} else if len(serverKey) != 16 {
			cb.Invoke(nil, "invalid server key length")
			return js.Undefined()
		}

		go func() {
			resp := make(chan imageResponse)
			req <- imageRequest{name, serverKey, resp}

			t := time.NewTimer(30 * time.Second)
			defer t.Stop()

			select {
			case r := <-resp:
				if r.err != nil {
					cb.Invoke(nil, r.err.Error())
					return
				}

				jsImageData := js.Global().Get("Uint8Array").New(len(r.data))
				js.CopyBytesToJS(jsImageData, r.data)

				jsBlob := js.Global().Get("Blob").New([]interface{}{jsImageData})
				jsBlobUrl := js.Global().Get("URL").Call("createObjectURL", jsBlob)
				cb.Invoke(jsBlobUrl, nil)
			case <-t.C:
				cb.Invoke(nil, "timeout")
			}
		}()

		return js.Undefined()
	}))
	select {}
}
