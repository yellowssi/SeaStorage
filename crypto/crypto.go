package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/klauspost/reedsolomon"
	"gitlab.com/SeaStorage/SeaStorage-TP/crypto"
	"gitlab.com/SeaStorage/SeaStorage-TP/storage"
	"gitlab.com/SeaStorage/SeaStorage/lib"
	"io"
	"os"
	"path"
)

func init() {
	if _, err := os.Stat(lib.DefaultTmpPath); os.IsNotExist(err) {
		err = os.MkdirAll(lib.DefaultTmpPath, 0755)
		if err != nil {
			panic(err)
		}
	}
}

func GenerateFileInfo(target string, dataShards, parShards int) (info storage.FileInfo, err error) {
	// File Encrypt
	inFile, err := os.Open(target)
	if err != nil {
		return
	}
	inFileInfo, err := inFile.Stat()
	if err != nil {
		return
	}
	outFile, err := os.OpenFile(path.Join(lib.DefaultTmpPath, inFileInfo.Name()+lib.EncryptSuffix), os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	keyAes := crypto.GenerateRandomAESKey(lib.AESKeySize)
	hash, err := EncryptFile(inFile, outFile, keyAes)
	if err != nil {
		return
	}
	inFile.Close()
	outFile.Close()
	err = os.Mkdir(path.Join(lib.DefaultTmpPath, hash), 0755)
	if err != nil {
		return
	}
	os.Rename(path.Join(lib.DefaultTmpPath, inFileInfo.Name()+lib.EncryptSuffix), path.Join(lib.DefaultTmpPath, hash, hash))

	// Split File
	f, err := os.Open(path.Join(lib.DefaultTmpPath, hash, hash))
	if err != nil {
		return
	}
	defer func() {
		f.Close()
		os.Remove(f.Name())
	}()
	fileInfo, err := f.Stat()
	if err != nil {
		return
	}
	hashes, fragmentSize, err := SplitFile(f, path.Join(lib.DefaultTmpPath, hash), dataShards, parShards)
	if err != nil {
		return
	}
	fragments := make([]*storage.Fragment, dataShards+parShards)
	for i := range fragments {
		fragments[i] = &storage.Fragment{
			Hash: hashes[i],
			Size: fragmentSize,
			Seas: make([]*storage.FragmentSea, 0),
		}
	}
	info = storage.FileInfo{
		Name:      inFileInfo.Name(),
		Size:      fileInfo.Size(),
		Hash:      hash,
		Key:       crypto.BytesToHex(keyAes),
		Fragments: fragments,
	}
	return
}

// AES CTR File Encryption
func EncryptFile(inFile, outFile *os.File, keyAes []byte) (hash string, err error) {
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
	_, err = outFile.Write(iv)
	if err != nil {
		return
	}

	hashes := make([][]byte, 0)
	buf := make([]byte, lib.BufferSize)

	for i := 0; i < int(size); i += lib.BufferSize {
		n, err := inFile.Read(buf)
		if err != nil && err != io.EOF {
			return hash, err
		}

		outBuf := make([]byte, n)
		ctr.XORKeyStream(outBuf, buf[:n])
		hashes = append(hashes, crypto.SHA512BytesFromBytes(outBuf))
		outFile.Write(outBuf)
	}
	hash = crypto.SHA512HexFromBytes(bytes.Join(hashes, []byte{}))
	return
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

	for i := lib.IvSize; i < int(size); i += lib.BufferSize {
		n, err := inFile.ReadAt(buf, int64(i))
		if err != nil && err != io.EOF {
			return hash, err
		}

		hashes = append(hashes, crypto.SHA512BytesFromBytes(buf[:n]))
		outBuf := make([]byte, n)
		ctr.XORKeyStream(outBuf, buf[:n])
		_, _ = outFile.Write(outBuf)
	}
	hash = crypto.SHA512HexFromBytes(bytes.Join(hashes, []byte{}))
	return
}

func SplitFile(inFile *os.File, outPath string, dataShards, parShards int) (hashes []string, fragmentSize int64, err error) {
	info, err := inFile.Stat()
	if err != nil {
		return
	}
	filename := info.Name()
	size := info.Size()
	if _, err := os.Stat(outPath); os.IsNotExist(err) {
		err = os.MkdirAll(outPath, 0644)
		if err != nil {
			return hashes, fragmentSize, err
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
			return hashes, fragmentSize, err
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
			return hashes, fragmentSize, err
		}
		if i == 0 {
			stat, _ := f.Stat()
			fragmentSize = stat.Size()
		}
		out[i] = f
		hashes[i], err = CalFileHash(out[i])
		if err != nil {
			return hashes, fragmentSize, err
		}
		f.Close()
	}
	return
}

func MergeFile(inPath string, hashes []string, outFile *os.File, originalSize, dataShards, parShards int) error {
	if len(hashes) != dataShards+parShards {
		return errors.New("the length of hash is not equal to shards")
	}
	dec, err := reedsolomon.NewStream(dataShards, parShards)
	if err != nil {
		return err
	}
	shards, size, err := openInput(inPath, hashes, dataShards, parShards)
	if err != nil {
		return err
	}
	ok, err := dec.Verify(shards)
	if !ok {
		shards, _, err := openInput(inPath, hashes, dataShards, parShards)
		out := make([]io.Writer, len(shards))
		for i := range out {
			if shards[i] == nil {
				out[i], err = os.Create(path.Join(inPath, hashes[i]))
				if err != nil {
					return err
				}
			}
		}
		err = dec.Reconstruct(shards, out)
		if err != nil {
			return err
		}
		for i := range out {
			if out[i] != nil {
				err = out[i].(*os.File).Close()
				if err != nil {
					return err
				}
			}
		}
		shards, _, err = openInput(inPath, hashes, dataShards, parShards)
		ok, err = dec.Verify(shards)
		if !ok || err != nil {
			return err
		}
	}
	shards, size, err = openInput(inPath, hashes, dataShards, parShards)
	err = dec.Join(outFile, shards, int64(dataShards)*size)
	if err != nil {
		return err
	}
	for i := range shards {
		defer func() {
			shards[i].(*os.File).Close()
			os.Remove(shards[i].(*os.File).Name())
		}()
	}
	return outFile.Truncate(int64(originalSize))
}

func openInput(inPath string, hashes []string, dataShards, parShards int) (r []io.Reader, size int64, err error) {
	// Create shards and load the data.
	shards := make([]io.Reader, dataShards+parShards)
	for i := range shards {
		f, err := os.Open(path.Join(inPath, hashes[i]))
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
