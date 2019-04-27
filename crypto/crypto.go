package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"github.com/klauspost/reedsolomon"
	"gitlab.com/SeaStorage/SeaStorage-TP/crypto"
	"gitlab.com/SeaStorage/SeaStorage-TP/storage"
	"gitlab.com/SeaStorage/SeaStorage/lib"
	"io"
	"os"
	"path"
)

func GenerateFileInfo(target string) (storage.FileInfo, error) {
	return storage.FileInfo{}, nil
}

// AES CTR With HMAC File Encryption
func EncryptFile(inFile, outFile *os.File, keyAes, keyHmac []byte) (hash string, err error) {
	info, err := inFile.Stat()
	if err != nil {
		return
	}
	size := info.Size()
	iv := make([]byte, lib.IvSize)
	_, err = rand.Read(iv)
	if err != nil {
		return
	}
	block, err := aes.NewCipher(keyAes)
	if err != nil {
		return
	}
	ctr := cipher.NewCTR(block, iv)
	h := hmac.New(sha256.New, keyHmac)
	_, err = outFile.Write(iv)
	if err != nil {
		return
	}
	h.Write(iv)

	hashes := make([][]byte, 0)
	buf := make([]byte, lib.BufferSize)

	for i := 0; i < int(size); i += lib.BufferSize {
		n, err := inFile.Read(buf)
		if err != nil && err != io.EOF {
			return hash, err
		}

		outBuf := make([]byte, n)
		ctr.XORKeyStream(outBuf, buf[:n])
		h.Write(outBuf)
		hashes = append(hashes, crypto.SHA512BytesFromBytes(outBuf))
		_, _ = outFile.Write(outBuf)
	}
	_, _ = outFile.Write(h.Sum(nil))
	hash = crypto.SHA512HexFromBytes(bytes.Join(hashes, []byte{}))
	return
}

// Verify HMAC
func VerifyHmac(inFile *os.File, keyHmac []byte) (bool, error) {
	info, err := inFile.Stat()
	if err != nil {
		return false, err
	}
	size := info.Size()
	fileHmac := make([]byte, lib.HmacSize)
	_, err = inFile.ReadAt(fileHmac, size-lib.HmacSize)
	if err != nil {
		return false, err
	}
	iv := make([]byte, lib.IvSize)
	_, err = inFile.Read(iv)
	if err != nil {
		return false, err
	}

	h := hmac.New(sha256.New, keyHmac)
	h.Write(iv)
	buf := make([]byte, lib.BufferSize)

	for i := lib.IvSize; i < int(size)-lib.HmacSize; i += lib.BufferSize {
		n, err := inFile.ReadAt(buf, int64(i))
		if err != nil && err != io.EOF {
			return false, err
		}
		if i == int(size)-lib.HmacSize-lib.BufferSize || err == io.EOF {
			n = int(size) - i - lib.HmacSize
		}
		h.Write(buf[:n])
	}
	return hmac.Equal(fileHmac, h.Sum(nil)), nil
}

// AES CTR File Decryption
func DecryptFile(inFile, outFile *os.File, key []byte) (hash string, err error) {
	info, err := inFile.Stat()
	if err != nil {
		return
	}
	size := info.Size()
	iv := make([]byte, lib.IvSize)
	_, err = inFile.Read(iv)
	if err != nil {
		return
	}
	block, err := aes.NewCipher(key)
	ctr := cipher.NewCTR(block, iv)
	buf := make([]byte, lib.BufferSize)
	hashes := make([][]byte, 0)

	for i := lib.IvSize; i < int(size)-lib.HmacSize; i += lib.BufferSize {
		n, err := inFile.ReadAt(buf, int64(i))
		if err != nil && err != io.EOF {
			return hash, err
		}
		if i == int(size)-lib.HmacSize-lib.BufferSize || err == io.EOF {
			n = int(size) - i - lib.HmacSize
		}

		hashes = append(hashes, crypto.SHA512BytesFromBytes(buf[:n]))
		outBuf := make([]byte, n)
		ctr.XORKeyStream(outBuf, buf[:n])
		_, _ = outFile.Write(outBuf)

		if err == io.EOF {
			break
		}
	}
	hash = crypto.SHA512HexFromBytes(bytes.Join(hashes, []byte{}))
	return
}

func SplitFile(inFile *os.File, outPath string, dataShards, parShards int) (hashes []string, err error) {
	info, err := inFile.Stat()
	if err != nil {
		return
	}
	filename := info.Name()
	size := info.Size()
	if _, err := os.Stat(outPath); os.IsNotExist(err) {
		err = os.MkdirAll(outPath, 0644)
		if err != nil {
			return hashes, err
		}
	}
	enc, err := reedsolomon.NewStream(dataShards, parShards)

	out := make([]*os.File, dataShards+parShards)
	for i := range out {
		outFilename := fmt.Sprintf("%s.%d", filename, i)
		out[i], err = os.Create(path.Join(outPath, outFilename))
		if err != nil {
			return
		}
	}
	data := make([]io.Writer, dataShards)
	for i := range data {
		data[i] = out[i]
	}
	err = enc.Split(inFile, data, size)
	if err != nil {
		return
	}
	input := make([]io.Reader, dataShards)
	for i := range data {
		out[i].Close()
		f, err := os.Open(out[i].Name())
		if err != nil {
			return hashes, err
		}
		input[i] = f
	}

	parity := make([]io.Writer, parShards)
	for i := range parity {
		parity[i] = out[dataShards+i]
	}
	err = enc.Encode(input, parity)
	if err != nil {
		return
	}

	hashes = make([]string, dataShards+parShards)
	for i := range out {
		out[i].Close()
		f, err := os.Open(out[i].Name())
		if err != nil {
			return hashes, err
		}
		out[i] = f
		hashes[i], err = CalFileHash(out[i])
		if err != nil {
			return hashes, err
		}
		f.Close()
	}
	return
}

func MergeFile(inPath, filename string, outFile *os.File, dataShards, parShards int) (hashes []string, err error) {
	dec, err := reedsolomon.NewStream(dataShards, parShards)
	if err != nil {
		return
	}
	shards, size, err := openInput(inPath, filename, dataShards, parShards)
	if err != nil {
		return
	}
	ok, err := dec.Verify(shards)
	if !ok {
		out := make([]io.Writer, len(shards))
		for i := range out {
			if shards[i] == nil {
				outFilename := fmt.Sprintf("%s.%d", filename, i)
				out[i], err = os.Create(path.Join(inPath, outFilename))
				if err != nil {
					return
				}
			}
		}
		err = dec.Reconstruct(shards, out)
		if err != nil {
			return
		}
		for i := range out {
			if out[i] != nil {
				err = out[i].(*os.File).Close()
				if err != nil {
					return
				}
			}
		}
		shards, size, err = openInput(inPath, filename, dataShards, parShards)
		ok, err = dec.Verify(shards)
		if !ok || err != nil {
			return
		}
	}
	shards, size, err = openInput(inPath, filename, dataShards, parShards)
	err = dec.Join(outFile, shards, int64(dataShards)*size)
	if err != nil {
		return
	}
	hashes = make([]string, dataShards+parShards)
	for i := range shards {
		hashes[i], err = CalFileHash(shards[i].(*os.File))
		if err != nil {
			return
		}
	}
	return
}

func openInput(inPath, filename string, dataShards, parShards int) (r []io.Reader, size int64, err error) {
	// Create shards and load the data.
	shards := make([]io.Reader, dataShards+parShards)
	for i := range shards {
		inFilename := fmt.Sprintf("%s.%d", filename, i)
		f, err := os.Open(path.Join(inPath, inFilename))
		if err != nil {
			shards[i] = nil
			continue
		} else {
			shards[i] = f
		}
		stat, err := f.Stat()
		if err != nil {
			return r, size, err
		}
		if stat.Size() > 0 {
			size = stat.Size()
		} else {
			shards[i] = nil
		}
	}
	return shards, size, nil
}

func CalFileHash(f *os.File) (hash string, err error) {
	info, err := f.Stat()
	if err != nil {
		return
	}
	size := info.Size()
	hashes := make([][]byte, 0)
	buf := make([]byte, lib.BufferSize)

	for i := 0; i < int(size); i += lib.BufferSize {
		n, err := f.ReadAt(buf, int64(i))
		if err != nil && err != io.EOF {
			return hash, err
		}
		hashes = append(hashes, crypto.SHA512BytesFromBytes(buf[:n]))
	}
	hash = crypto.SHA512HexFromBytes(bytes.Join(hashes, []byte{}))
	return
}
