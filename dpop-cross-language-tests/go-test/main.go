package main

import (
	"encoding/json"
	"fmt"
	"os"

	dpop "github.com/prodnull/unix-oidc/go-oauth-dpop"
)

type ProofData struct {
	Proof      string `json:"proof"`
	Thumbprint string `json:"thumbprint"`
	Method     string `json:"method"`
	Target     string `json:"target"`
}

const (
	method = "POST"
	target = "https://cross-test.example.com/token"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <generate|validate> [proof_file]\n", os.Args[0])
		os.Exit(1)
	}

	switch os.Args[1] {
	case "generate":
		outputFile := "go_proof.json"
		if len(os.Args) > 2 {
			outputFile = os.Args[2]
		}
		generate(outputFile)
	case "validate":
		if len(os.Args) < 3 {
			fmt.Fprintf(os.Stderr, "Usage: %s validate <proof_file>\n", os.Args[0])
			os.Exit(1)
		}
		validate(os.Args[2])
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
		os.Exit(1)
	}
}

func generate(outputFile string) {
	client, err := dpop.NewClient()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create client: %v\n", err)
		os.Exit(1)
	}

	proof, err := client.CreateProof(method, target, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create proof: %v\n", err)
		os.Exit(1)
	}

	data := ProofData{
		Proof:      proof,
		Thumbprint: client.Thumbprint(),
		Method:     method,
		Target:     target,
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to marshal JSON: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(outputFile, jsonData, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Generated proof: %s\n", outputFile)
}

func validate(inputFile string) {
	jsonData, err := os.ReadFile(inputFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read file: %v\n", err)
		os.Exit(1)
	}

	var data ProofData
	if err := json.Unmarshal(jsonData, &data); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse JSON: %v\n", err)
		os.Exit(1)
	}

	config := dpop.Config{
		MaxProofAgeSecs: 300, // 5 minutes for cross-language tests
		RequireNonce:    false,
		ExpectedMethod:  data.Method,
		ExpectedTarget:  data.Target,
	}

	thumbprint, err := dpop.ValidateProof(data.Proof, config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: Validation error: %v\n", err)
		os.Exit(1)
	}

	if err := dpop.VerifyBinding(thumbprint, data.Thumbprint); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: Thumbprint mismatch: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("PASS: %s validated successfully\n", inputFile)
}
