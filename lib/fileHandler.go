package lib

import (
	"io"
	"os"
)

func Copy(srcPath, dstPath string) error {
	src, err := os.OpenFile(srcPath, os.O_RDONLY, 0600)
	defer src.Close()
	if err != nil {
		return err
	}
	dst, err := os.OpenFile(dstPath, os.O_WRONLY | os.O_CREATE, 0600)
	defer dst.Close()
	if err != nil {
		return err
	}
	_, err = io.Copy(dst, src)
	return err
}
