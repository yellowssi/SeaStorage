package p2p

import (
	tpUser "gitlab.com/SeaStorage/SeaStorage-TP/user"
	"os"
)

func UploadFile(inFile *os.File, dst string, signature tpUser.OperationSignature) error {
	return nil
}

func DownloadFile(hash, dst string) error {
	return nil
}
