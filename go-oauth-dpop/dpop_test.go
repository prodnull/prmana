package dpop

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestNewClient(t *testing.T) {
	client, err := NewClient()
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	if client.Thumbprint() == "" {
		t.Error("thumbprint should not be empty")
	}

	// SHA-256 = 32 bytes = 43 base64url chars
	if len(client.Thumbprint()) != 43 {
		t.Errorf("thumbprint should be 43 chars, got %d", len(client.Thumbprint()))
	}
}

func TestCreateProof(t *testing.T) {
	client, err := NewClient()
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	proof, err := client.CreateProof("POST", "https://example.com/token", nil)
	if err != nil {
		t.Fatalf("failed to create proof: %v", err)
	}

	// JWT format: header.claims.signature
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		t.Errorf("proof should have 3 parts, got %d", len(parts))
	}
}

func TestProofContainsCorrectHeader(t *testing.T) {
	client, err := NewClient()
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	proof, err := client.CreateProof("GET", "https://api.example.com/resource", nil)
	if err != nil {
		t.Fatalf("failed to create proof: %v", err)
	}

	parts := strings.Split(proof, ".")
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("failed to decode header: %v", err)
	}

	var header struct {
		Typ string `json:"typ"`
		Alg string `json:"alg"`
		Jwk struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
		} `json:"jwk"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		t.Fatalf("failed to parse header: %v", err)
	}

	if header.Typ != "dpop+jwt" {
		t.Errorf("typ should be dpop+jwt, got %s", header.Typ)
	}
	if header.Alg != "ES256" {
		t.Errorf("alg should be ES256, got %s", header.Alg)
	}
	if header.Jwk.Kty != "EC" {
		t.Errorf("kty should be EC, got %s", header.Jwk.Kty)
	}
	if header.Jwk.Crv != "P-256" {
		t.Errorf("crv should be P-256, got %s", header.Jwk.Crv)
	}
}

func TestProofContainsCorrectClaims(t *testing.T) {
	client, err := NewClient()
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	nonce := "server-nonce-123"
	proof, err := client.CreateProof("POST", "https://api.example.com/token", &nonce)
	if err != nil {
		t.Fatalf("failed to create proof: %v", err)
	}

	parts := strings.Split(proof, ".")
	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("failed to decode claims: %v", err)
	}

	var claims Claims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		t.Fatalf("failed to parse claims: %v", err)
	}

	if claims.HTM != "POST" {
		t.Errorf("htm should be POST, got %s", claims.HTM)
	}
	if claims.HTU != "https://api.example.com/token" {
		t.Errorf("htu should be https://api.example.com/token, got %s", claims.HTU)
	}
	if claims.Nonce == nil || *claims.Nonce != "server-nonce-123" {
		t.Error("nonce should be server-nonce-123")
	}
	if claims.JTI == "" {
		t.Error("jti should not be empty")
	}
	if claims.IAT <= 0 {
		t.Error("iat should be positive")
	}
}

func TestUniqueJTI(t *testing.T) {
	client, err := NewClient()
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	proof1, _ := client.CreateProof("GET", "https://example.com", nil)
	proof2, _ := client.CreateProof("GET", "https://example.com", nil)

	parts1 := strings.Split(proof1, ".")
	parts2 := strings.Split(proof2, ".")

	claims1Bytes, _ := base64.RawURLEncoding.DecodeString(parts1[1])
	claims2Bytes, _ := base64.RawURLEncoding.DecodeString(parts2[1])

	var claims1, claims2 Claims
	json.Unmarshal(claims1Bytes, &claims1)
	json.Unmarshal(claims2Bytes, &claims2)

	if claims1.JTI == claims2.JTI {
		t.Error("JTIs should be unique")
	}
}

func TestProofWithATH(t *testing.T) {
	client, err := NewClient()
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	accessToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test"
	proof, err := client.CreateProofWithATH("GET", "https://api.example.com/resource", nil, accessToken)
	if err != nil {
		t.Fatalf("failed to create proof: %v", err)
	}

	parts := strings.Split(proof, ".")
	claimsBytes, _ := base64.RawURLEncoding.DecodeString(parts[1])

	var claims Claims
	json.Unmarshal(claimsBytes, &claims)

	if claims.ATH == nil {
		t.Error("ath should be present")
	}
	// SHA-256 = 43 base64url chars
	if len(*claims.ATH) != 43 {
		t.Errorf("ath should be 43 chars, got %d", len(*claims.ATH))
	}
}

func TestValidateProof(t *testing.T) {
	client, err := NewClient()
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	proof, err := client.CreateProof("POST", "https://example.com/token", nil)
	if err != nil {
		t.Fatalf("failed to create proof: %v", err)
	}

	config := Config{
		MaxProofAgeSecs: 60,
		RequireNonce:    false,
		ExpectedMethod:  "POST",
		ExpectedTarget:  "https://example.com/token",
	}

	thumbprint, err := ValidateProof(proof, config)
	if err != nil {
		t.Fatalf("validation failed: %v", err)
	}

	if thumbprint != client.Thumbprint() {
		t.Errorf("thumbprint mismatch: expected %s, got %s", client.Thumbprint(), thumbprint)
	}
}

func TestValidateProofWithNonce(t *testing.T) {
	client, err := NewClient()
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	nonce := "abc123"
	proof, err := client.CreateProof("POST", "https://example.com/token", &nonce)
	if err != nil {
		t.Fatalf("failed to create proof: %v", err)
	}

	config := Config{
		MaxProofAgeSecs: 60,
		RequireNonce:    true,
		ExpectedNonce:   &nonce,
		ExpectedMethod:  "POST",
		ExpectedTarget:  "https://example.com/token",
	}

	_, err = ValidateProof(proof, config)
	if err != nil {
		t.Fatalf("validation failed: %v", err)
	}
}

func TestRejectWrongMethod(t *testing.T) {
	client, err := NewClient()
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	proof, _ := client.CreateProof("GET", "https://example.com/token", nil)

	config := Config{
		MaxProofAgeSecs: 60,
		ExpectedMethod:  "POST",
		ExpectedTarget:  "https://example.com/token",
	}

	_, err = ValidateProof(proof, config)
	if err == nil {
		t.Error("should reject wrong method")
	}
}

func TestRejectWrongTarget(t *testing.T) {
	client, err := NewClient()
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	proof, _ := client.CreateProof("POST", "https://other.com/token", nil)

	config := Config{
		MaxProofAgeSecs: 60,
		ExpectedMethod:  "POST",
		ExpectedTarget:  "https://example.com/token",
	}

	_, err = ValidateProof(proof, config)
	if err == nil {
		t.Error("should reject wrong target")
	}
}

func TestRejectWrongNonce(t *testing.T) {
	client, err := NewClient()
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	wrong := "wrong"
	proof, _ := client.CreateProof("POST", "https://example.com/token", &wrong)

	correct := "correct"
	config := Config{
		MaxProofAgeSecs: 60,
		RequireNonce:    true,
		ExpectedNonce:   &correct,
		ExpectedMethod:  "POST",
		ExpectedTarget:  "https://example.com/token",
	}

	_, err = ValidateProof(proof, config)
	if err == nil {
		t.Error("should reject wrong nonce")
	}
}

func TestVerifyBinding(t *testing.T) {
	client, err := NewClient()
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	proof, _ := client.CreateProof("POST", "https://example.com/token", nil)

	config := Config{
		MaxProofAgeSecs: 60,
		ExpectedMethod:  "POST",
		ExpectedTarget:  "https://example.com/token",
	}

	proofThumbprint, err := ValidateProof(proof, config)
	if err != nil {
		t.Fatalf("validation failed: %v", err)
	}

	// Should match
	if err := VerifyBinding(proofThumbprint, client.Thumbprint()); err != nil {
		t.Errorf("binding verification failed: %v", err)
	}

	// Should not match
	if err := VerifyBinding(proofThumbprint, "wrong-thumbprint"); err == nil {
		t.Error("should reject wrong thumbprint")
	}
}

func TestReplayDetection(t *testing.T) {
	client, err := NewClient()
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	proof, _ := client.CreateProof("POST", "https://replay-test.example.com/token", nil)

	config := Config{
		MaxProofAgeSecs: 60,
		ExpectedMethod:  "POST",
		ExpectedTarget:  "https://replay-test.example.com/token",
	}

	// First use should succeed
	_, err = ValidateProof(proof, config)
	if err != nil {
		t.Fatalf("first validation should succeed: %v", err)
	}

	// Second use should be detected as replay
	_, err = ValidateProof(proof, config)
	if err == nil {
		t.Error("should detect replay")
	}
	if err != ErrReplayDetected {
		t.Errorf("expected ErrReplayDetected, got %v", err)
	}
}

func TestConstantTimeEq(t *testing.T) {
	if !constantTimeEq("hello", "hello") {
		t.Error("equal strings should match")
	}
	if constantTimeEq("hello", "world") {
		t.Error("different strings should not match")
	}
	if constantTimeEq("hello", "hell") {
		t.Error("different length strings should not match")
	}
	if constantTimeEq("", "x") {
		t.Error("empty vs non-empty should not match")
	}
	if !constantTimeEq("", "") {
		t.Error("two empty strings should match")
	}
}

func TestRejectShortCoordinates(t *testing.T) {
	// Create a proof with shortened coordinates (31 bytes instead of 32)
	// This tests that we reject non-standard JWK coordinates
	shortX := base64.RawURLEncoding.EncodeToString(make([]byte, 31)) // 31 bytes
	shortY := base64.RawURLEncoding.EncodeToString(make([]byte, 31)) // 31 bytes

	// Construct a minimal DPoP proof header with short coordinates
	header := map[string]interface{}{
		"typ": "dpop+jwt",
		"alg": "ES256",
		"jwk": map[string]string{
			"kty": "EC",
			"crv": "P-256",
			"x":   shortX,
			"y":   shortY,
		},
	}
	headerBytes, _ := json.Marshal(header)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerBytes)

	claims := map[string]interface{}{
		"jti": "test-jti",
		"htm": "POST",
		"htu": "https://example.com/token",
		"iat": 1234567890,
	}
	claimsBytes, _ := json.Marshal(claims)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsBytes)

	// Fake signature (will fail anyway during key extraction)
	sigB64 := base64.RawURLEncoding.EncodeToString(make([]byte, 64))

	proof := headerB64 + "." + claimsB64 + "." + sigB64

	config := Config{
		MaxProofAgeSecs: 60,
		ExpectedMethod:  "POST",
		ExpectedTarget:  "https://example.com/token",
	}

	_, err := ValidateProof(proof, config)
	if err == nil {
		t.Error("should reject proof with short coordinates")
	}

	// Verify error message mentions coordinate length
	if ve, ok := err.(*ValidationError); ok {
		if !strings.Contains(ve.Message, "32 bytes") {
			t.Errorf("error should mention 32 bytes requirement, got: %s", ve.Message)
		}
	}
}
