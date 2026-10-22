package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: virus_total <file_name>")
		os.Exit(23)
	}
	fileToBeScanned := os.Args[1]

	fileInfo, err := os.Stat(fileToBeScanned)

	if err != nil {
		fmt.Fprintln(os.Stderr, "Cannot open ", fileToBeScanned)
		os.Exit(23)
	}

	if fileInfo.IsDir() {
		fmt.Fprintln(os.Stderr, "Directories are not supported.")
		os.Exit(23)
	}

	if fileInfo.Size() > 32_000_000 {
		fmt.Println("For now this tool only supports files upto 32MB only")
		os.Exit(20)
	}

	f, err := os.Open(fileToBeScanned)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Cannot read ", fileToBeScanned)
		os.Exit(23)
	}
	defer f.Close()
	h := sha256.New()

	if _, err := io.Copy(h, f); err != nil {
		fmt.Fprintln(os.Stderr, "Cannot extract hash of ", fileToBeScanned)
		os.Exit(23)
	}

	digest := h.Sum(nil)
	hash := hex.EncodeToString(digest)

	fmt.Println(hash)

}
