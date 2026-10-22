package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"fmt"
	"io"
	"net/http"
	"os"
)

type ExistingVTResForHash struct {
	Data struct {
		Id         string `json:"id"`
		Type       string `json:"type"`
		Attributes struct {
			LastAnalysisDate  int64  `json:"last_analysis_date"`
			MeaningFulName    string `json:"meaningful_name"`
			LastAnalysisStats struct {
				Malicious       int32 `json:"malicious"`
				Suspicious      int32 `json:"suspicious"`
				Undetected      int32 `json:"undetected"`
				Harmless        int32 `json:"harmless"`
				Timeout         int32 `json:"Timeout"`
				Failure         int32 `json:"failure"`
				TypeUnsupported int32 `json:"type-unsupported"`
			} `json:"last_analysis_stats"`
			LastAnalysisResults map[string]EngineResult `json:"last_analysis_results"`
		} `json:"attributes"`
		Links struct {
			Self string `json:"self"`
		} `json:"links"`
	} `json:"data"`
}

type EngineResult struct {
	Method        string  `json:"method"`
	EngineName    string  `json:"engine_name"`
	EngineVersion string  `json:"engine_version"`
	EngineUpdate  string  `json:"engine_update"`
	Category      string  `json:"category"`
	Result        *string `json:"result"`
}

func main() {
	report_by_hash_url := "https://www.virustotal.com/api/v3/files/"
	VT_API_TOKEN, token_present := os.LookupEnv("VIRUS_TOTAL_API_TOKEN")

	if !token_present {
		fmt.Fprintln(os.Stderr, "Virus total api key is not avilable")
		os.Exit(23)
	}

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

	req, _ := http.NewRequest("GET", report_by_hash_url+hash, nil)
	req.Header.Add("accept", "application/json")
	req.Header.Add("x-apikey", VT_API_TOKEN)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "VT api error: %v", err)
		os.Exit(23)
	}
	defer res.Body.Close()

	body, _ := io.ReadAll(res.Body)

	var t ExistingVTResForHash

	err = json.Unmarshal(body, &t)

	if err != nil {
		fmt.Fprintf(os.Stderr, "JSON unmarshling error\n")

	}

	fmt.Println(t)

}
