// Copyright © 2019 yellowsea <hh1271941291@gmail.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package crypto provides the file utilities. Use this package's utilities
// to prepare for uploading file and get data from downloaded files.
package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path"

	"github.com/klauspost/reedsolomon"
	tpCrypto "gitlab.com/SeaStorage/SeaStorage-TP/crypto"
	tpStorage "gitlab.com/SeaStorage/SeaStorage-TP/storage"
	"gitlab.com/SeaStorage/SeaStorage/lib"
)

func init() {
	if _, err := os.Stat(lib.DefaultTmpPath); os.IsNotExist(err) {
		err = os.MkdirAll(lib.DefaultTmpPath, 0755)
		if err != nil {
			panic(err)
		}
	}
}

// GenerateFileInfo generate the information of file for SeaStorage file system.
// If the size of file smaller than the default large file size limitation,
// the file will be split using RS erasure coding,
// else the file will keep origin
func GenerateFileInfo(target, publicKey string, dataShards, parShards int) (info tpStorage.FileInfo, err error) {
	// File Encrypt
	inFile, err := os.Open(target)
	if err != nil {
		return
	}
	inFileInfo, err := inFile.Stat()
	if err != nil {
		return
	}
	keyAes := tpCrypto.GenerateRandomAESKey(lib.AESKeySize)
	keyEncrypt, err := tpCrypto.Encryption(publicKey, tpCrypto.BytesToHex(keyAes))
	if err != nil {
		return
	}
	outFile, err := os.OpenFile(path.Join(lib.DefaultTmpPath, inFileInfo.Name()+lib.EncryptSuffix), os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
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
	var f *os.File
	var fileInfo os.FileInfo
	if inFileInfo.Size() >= lib.DefaultLargeFileSize {
		f, err = os.Open(path.Join(lib.DefaultTmpPath, hash, hash))
		if err != nil {
			return
		}
		defer func() {
			f.Close()
		}()
		fileInfo, err = f.Stat()
		if err != nil {
			return
		}
		info = tpStorage.FileInfo{
			Name: inFileInfo.Name(),
			Size: fileInfo.Size(),
			Hash: hash,
			Key:  tpCrypto.BytesToHex(keyEncrypt),
			Fragments: []*tpStorage.Fragment{{
				Hash: hash,
				Size: inFileInfo.Size(),
				Seas: make([]*tpStorage.FragmentSea, 0),
			}},
		}
	} else {
		f, err = os.Open(path.Join(lib.DefaultTmpPath, hash, hash))
		if err != nil {
			return
		}
		defer func() {
			f.Close()
			os.Remove(f.Name())
		}()
		fileInfo, err = f.Stat()
		if err != nil {
			return
		}
		var hashes []string
		var fragmentSize int64
		hashes, fragmentSize, err = SplitFile(f, path.Join(lib.DefaultTmpPath, hash), dataShards, parShards)
		if err != nil {
			return
		}
		fragments := make([]*tpStorage.Fragment, dataShards+parShards)
		for i := range fragments {
			fragments[i] = &tpStorage.Fragment{
				Hash: hashes[i],
				Size: fragmentSize,
				Seas: make([]*tpStorage.FragmentSea, 0),
			}
		}
		info = tpStorage.FileInfo{
			Name:      inFileInfo.Name(),
			Size:      fileInfo.Size(),
			Hash:      hash,
			Key:       tpCrypto.BytesToHex(keyEncrypt),
			Fragments: fragments,
		}
	}
	return
}

// EncryptFile encrypt the file using AES-CTR. After encryption, calculate the hash of file.
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
		hashes = append(hashes, tpCrypto.SHA512BytesFromBytes(outBuf))
		outFile.Write(outBuf)
	}
	hash = tpCrypto.SHA512HexFromBytes(bytes.Join(hashes, []byte{}))
	return
}

// DecryptFile decrypt the file using AES-CTR. After decryption, calculate the hash of file.
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

		hashes = append(hashes, tpCrypto.SHA512BytesFromBytes(buf[:n]))
		outBuf := make([]byte, n)
		ctr.XORKeyStream(outBuf, buf[:n])
		_, _ = outFile.Write(outBuf)
	}
	hash = tpCrypto.SHA512HexFromBytes(bytes.Join(hashes, []byte{}))
	return
}

// SplitFile split file using Reed-solomon erasure coding.
// After split, calculate each fragment's infos (hash & size).
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

// MergeFile merge fragments using Reed-solomon erasure coding.
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

// CalFileHash calculate the hash of file.
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
		hashes = append(hashes, tpCrypto.SHA512BytesFromBytes(buf[:n]))
	}
	hash = tpCrypto.SHA512HexFromBytes(bytes.Join(hashes, []byte{}))
	return
}
