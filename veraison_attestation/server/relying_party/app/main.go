package main

import (
	"bytes"
        "crypto/tls"
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
)

func main() {
	targetBaseURL := "https://verification-service:8080" // Base URL for the forwarding target
	log.Println("Relying party is starting...")
	server := http.Server{
		Addr:    ":8087",
		Handler: nil,
	}

	handler := func(w http.ResponseWriter, req *http.Request) {
		log.Printf("Received request: %s %s\n", req.Method, req.URL.String())

		// Add the original request's path and query to the new URL
		targetURL := targetBaseURL + req.URL.Path
		if len(req.URL.RawQuery) > 0 {
			targetURL += "?" + req.URL.RawQuery
		}

		// Create a request for the forwarding endpoint
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}
		proxyReq, err := http.NewRequest(req.Method, targetURL, req.Body)
		if err != nil {
			log.Printf("Error creating request: %v\n", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Copy headers
		proxyReq.Header = req.Header

		// Forward the request
		resp, err := client.Do(proxyReq)
		if err != nil {
			log.Printf("Error forwarding request: %v\n", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()
		log.Printf("Received response: %s\n", resp.Status)

		if strings.HasPrefix(req.URL.Path, "/challenge-response/v1/session/") {
			// Process the attestation result without consuming the response body
			processAttestationResult(w, resp)
		} else {
			// For other paths, just copy the response
			copyResponse(w, resp)
		}
	}

	// Set up server routes
	http.HandleFunc("/challenge-response/v1/newSession", handler)
	http.HandleFunc("/challenge-response/v1/session/", handler)

	log.Fatal(server.ListenAndServe())
}

// processAttestationResult processes the attestation result without consuming the response body
func processAttestationResult(w http.ResponseWriter, resp *http.Response) {
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading response body: %v\n", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Parse the JSON response to extract the result
	var dataMap map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &dataMap); err != nil {
		log.Printf("Error parsing JSON: %v\n", err)
		return
	}

	result, ok := dataMap["result"].(string)
	if !ok {
		log.Println("Error: 'result' key not found or is not a string")
		return
	}

	// Write the result to a temporary file for further processing
	tempFile, err := ioutil.TempFile("", "*.jwt")
	if err != nil {
		log.Printf("Error creating temp file: %v\n", err)
		return
	}
	defer os.Remove(tempFile.Name())

	if _, err := tempFile.WriteString(result); err != nil {
		log.Printf("Error writing to temp file: %v\n", err)
		return
	}
	tempFile.Close()

	// Execute a command with the temp file
	cmd := exec.Command("arc", "verify", "--pkey", "pkey.json", "--alg", "ES256", "--verbose", tempFile.Name())
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Error executing command: %v\n", err)
	} else {
		log.Printf("Attestation result: %s", string(output))
	}

	// Reset the response body so it can be used again in the original handler
	resp.Body = ioutil.NopCloser(bytes.NewReader(bodyBytes))
	copyResponse(w, resp)
}

// copyResponse copies the response from the forwarding service to the original client
func copyResponse(w http.ResponseWriter, resp *http.Response) {
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}
