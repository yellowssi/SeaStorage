package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
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
	inFile.Close()
	outFile.Close()

	// Split File
	f, err := os.Open(path.Join(lib.DefaultTmpPath, inFileInfo.Name()+lib.EncryptSuffix))
	if err != nil {
		return
	}
	err = os.Mkdir(path.Join(lib.DefaultTmpPath, hash), 0755)
	hashes, err := SplitFile(f, path.Join(lib.DefaultTmpPath, hash), dataShards, parShards)
	if err != nil {
		return
	}
	fragments := make([]*storage.Fragment, dataShards+parShards)
	for i := range fragments {
		fragments[i] = &storage.Fragment{
			Hash: hashes[i],
			Seas: make([]*storage.FragmentSea, 0),
		}
	}
	info = storage.FileInfo{
		Name: inFileInfo.Name(),
		Size: uint(inFileInfo.Size()),
		Hash: hash,
		Key: crypto.BytesToHex(keyAes),
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
		_, _ = outFile.Write(outBuf)
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
		if i == int(size)-lib.BufferSize || err == io.EOF {
			n = int(size) - i - lib.HmacSize
		}

		hashes = append(hashes, crypto.SHA512BytesFromBytes(buf[:n]))
		outBuf := make([]byte, n)
		ctr.XORKeyStream(outBuf, buf[:n])
		_, _ = outFile.Write(outBuf)
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
