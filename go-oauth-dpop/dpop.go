// Package dpop implements OAuth 2.0 DPoP (Demonstrating Proof of Possession) per RFC 9449.
//
// DPoP is a mechanism for sender-constraining OAuth 2.0 tokens by binding them to
// a cryptographic key held by the client. This prevents stolen tokens from being
// used by attackers who don't possess the private key.
//
// # Client Usage
//
//	client, err := dpop.NewClient()
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Get thumbprint for token binding
//	thumbprint := client.Thumbprint()
//
//	// Generate proof for HTTP request
//	proof, err := client.CreateProof("POST", "https://api.example.com/token", nil)
//
// # Server Usage
//
//	config := dpop.Config{
//	    MaxProofAgeSecs: 60,
//	    ExpectedMethod:  "POST",
//	    ExpectedTarget:  "https://api.example.com/token",
//	}
//
//	thumbprint, err := dpop.ValidateProof(proof, config)
//	if err != nil {
//	    // Handle validation error
//	}
package dpop

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Client generates DPoP proofs for HTTP requests.
type Client struct {
	privateKey *ecdsa.PrivateKey
	thumbprint string
}

// NewClient creates a new DPoP client with a random P-256 keypair.
func NewClient() (*Client, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	thumbprint := computeThumbprint(&privateKey.PublicKey)

	return &Client{
		privateKey: privateKey,
		thumbprint: thumbprint,
	}, nil
}

// NewClientFromKey creates a DPoP client from an existing private key.
func NewClientFromKey(privateKey *ecdsa.PrivateKey) *Client {
	return &Client{
		privateKey: privateKey,
		thumbprint: computeThumbprint(&privateKey.PublicKey),
	}
}

// Thumbprint returns the JWK thumbprint of this client's public key.
// This should be used for the cnf.jkt claim in tokens.
func (c *Client) Thumbprint() string {
	return c.thumbprint
}

// PublicKey returns the client's public key.
func (c *Client) PublicKey() *ecdsa.PublicKey {
	return &c.privateKey.PublicKey
}

// CreateProof generates a DPoP proof for an HTTP request.
func (c *Client) CreateProof(method, target string, nonce *string) (string, error) {
	return c.createProofInternal(method, target, nonce, nil)
}

// CreateProofWithATH generates a DPoP proof with an access token hash.
// Use this when accessing protected resources with a DPoP-bound access token.
func (c *Client) CreateProofWithATH(method, target string, nonce *string, accessToken string) (string, error) {
	hash := sha256.Sum256([]byte(accessToken))
	ath := base64.RawURLEncoding.EncodeToString(hash[:])
	return c.createProofInternal(method, target, nonce, &ath)
}

func (c *Client) createProofInternal(method, target string, nonce, ath *string) (string, error) {
	// Get coordinates - must be zero-padded to 32 bytes for P-256
	xBytes := make([]byte, 32)
	yBytes := make([]byte, 32)
	c.privateKey.PublicKey.X.FillBytes(xBytes)
	c.privateKey.PublicKey.Y.FillBytes(yBytes)
	x := base64.RawURLEncoding.EncodeToString(xBytes)
	y := base64.RawURLEncoding.EncodeToString(yBytes)

	// Build header
	header := map[string]interface{}{
		"typ": "dpop+jwt",
		"alg": "ES256",
		"jwk": map[string]string{
			"kty": "EC",
			"crv": "P-256",
			"x":   x,
			"y":   y,
		},
	}

	// Build claims
	claims := map[string]interface{}{
		"jti": uuid.New().String(),
		"htm": method,
		"htu": target,
		"iat": time.Now().Unix(),
	}
	if nonce != nil {
		claims["nonce"] = *nonce
	}
	if ath != nil {
		claims["ath"] = *ath
	}

	// Encode header and claims
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal header: %w", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal claims: %w", err)
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	// Sign
	message := headerB64 + "." + claimsB64
	hash := sha256.Sum256([]byte(message))
	r, s, err := ecdsa.Sign(rand.Reader, c.privateKey, hash[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign: %w", err)
	}

	// ES256 signature is r || s, each 32 bytes
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	return message + "." + sigB64, nil
}

// Claims represents DPoP proof claims per RFC 9449.
type Claims struct {
	JTI   string  `json:"jti"`
	HTM   string  `json:"htm"`
	HTU   string  `json:"htu"`
	IAT   int64   `json:"iat"`
	Nonce *string `json:"nonce,omitempty"`
	ATH   *string `json:"ath,omitempty"`
}

// EcPublicJwk represents an EC public key in JWK format.
type EcPublicJwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// Config holds DPoP validation configuration.
type Config struct {
	MaxProofAgeSecs int64
	RequireNonce    bool
	ExpectedNonce   *string
	ExpectedMethod  string
	ExpectedTarget  string
}

// ValidationError represents a DPoP validation error.
type ValidationError struct {
	Code    string
	Message string
}

func (e *ValidationError) Error() string {
	return e.Message
}

var (
	ErrInvalidFormat      = &ValidationError{"INVALID_FORMAT", "invalid proof format"}
	ErrInvalidHeader      = &ValidationError{"INVALID_HEADER", "invalid header"}
	ErrInvalidSignature   = &ValidationError{"INVALID_SIGNATURE", "invalid signature"}
	ErrMissingJwk         = &ValidationError{"MISSING_JWK", "missing JWK in header"}
	ErrUnsupportedAlg     = &ValidationError{"UNSUPPORTED_ALG", "unsupported algorithm"}
	ErrProofExpired       = &ValidationError{"PROOF_EXPIRED", "proof expired"}
	ErrMethodMismatch     = &ValidationError{"METHOD_MISMATCH", "method mismatch"}
	ErrTargetMismatch     = &ValidationError{"TARGET_MISMATCH", "target mismatch"}
	ErrNonceMismatch      = &ValidationError{"NONCE_MISMATCH", "nonce mismatch"}
	ErrMissingNonce       = &ValidationError{"MISSING_NONCE", "missing nonce"}
	ErrReplayDetected     = &ValidationError{"REPLAY_DETECTED", "replay detected"}
	ErrInvalidKeyParams   = &ValidationError{"INVALID_KEY_PARAMS", "invalid key parameters"}
	ErrThumbprintMismatch = &ValidationError{"THUMBPRINT_MISMATCH", "thumbprint mismatch"}
)

// JTI cache for replay protection
var (
	jtiCache      = make(map[string]time.Time)
	jtiCacheMutex sync.RWMutex
	lastCleanup   = time.Now()
)

func checkAndRecordJTI(jti string, ttl time.Duration) bool {
	jtiCacheMutex.Lock()
	defer jtiCacheMutex.Unlock()

	// Maybe cleanup
	now := time.Now()
	if now.Sub(lastCleanup) > 5*time.Minute {
		for k, exp := range jtiCache {
			if exp.Before(now) {
				delete(jtiCache, k)
			}
		}
		lastCleanup = now
	}

	// Check if exists
	if exp, exists := jtiCache[jti]; exists && exp.After(now) {
		return false // Replay
	}

	// Record
	jtiCache[jti] = now.Add(ttl)
	return true
}

// ValidateProof validates a DPoP proof and returns the JWK thumbprint.
func ValidateProof(proof string, config Config) (string, error) {
	// Split proof
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		return "", ErrInvalidFormat
	}

	// Decode header
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", ErrInvalidFormat
	}

	var header struct {
		Typ string       `json:"typ"`
		Alg string       `json:"alg"`
		Jwk *EcPublicJwk `json:"jwk"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return "", ErrInvalidHeader
	}

	// Verify typ
	if header.Typ != "dpop+jwt" {
		return "", ErrInvalidHeader
	}

	// Verify alg
	if header.Alg != "ES256" {
		return "", &ValidationError{"UNSUPPORTED_ALG", fmt.Sprintf("unsupported algorithm: %s", header.Alg)}
	}

	// Verify JWK present
	if header.Jwk == nil {
		return "", ErrMissingJwk
	}

	// Decode signature
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", ErrInvalidSignature
	}

	// Convert JWK to public key
	pubKey, err := jwkToPublicKey(header.Jwk)
	if err != nil {
		return "", err
	}

	// Verify signature
	message := parts[0] + "." + parts[1]
	hash := sha256.Sum256([]byte(message))

	if len(sigBytes) != 64 {
		return "", ErrInvalidSignature
	}
	r := new(big.Int).SetBytes(sigBytes[:32])
	s := new(big.Int).SetBytes(sigBytes[32:])

	if !ecdsa.Verify(pubKey, hash[:], r, s) {
		return "", ErrInvalidSignature
	}

	// Decode claims
	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", ErrInvalidFormat
	}

	var claims Claims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return "", ErrInvalidFormat
	}

	// Validate iat
	now := time.Now().Unix()
	if now-claims.IAT > config.MaxProofAgeSecs {
		return "", ErrProofExpired
	}
	if claims.IAT > now+5 {
		return "", ErrProofExpired
	}

	// Validate method
	if claims.HTM != config.ExpectedMethod {
		return "", &ValidationError{"METHOD_MISMATCH", fmt.Sprintf("expected %s, got %s", config.ExpectedMethod, claims.HTM)}
	}

	// Validate target
	if claims.HTU != config.ExpectedTarget {
		return "", &ValidationError{"TARGET_MISMATCH", fmt.Sprintf("expected %s, got %s", config.ExpectedTarget, claims.HTU)}
	}

	// Validate nonce
	if config.RequireNonce {
		if claims.Nonce == nil {
			return "", ErrMissingNonce
		}
		if config.ExpectedNonce != nil && !constantTimeEq(*claims.Nonce, *config.ExpectedNonce) {
			return "", ErrNonceMismatch
		}
	}

	// JTI replay protection
	ttl := time.Duration(config.MaxProofAgeSecs+5) * time.Second
	if !checkAndRecordJTI(claims.JTI, ttl) {
		return "", ErrReplayDetected
	}

	// Compute thumbprint
	thumbprint := computeThumbprint(pubKey)
	return thumbprint, nil
}

// VerifyBinding verifies that the proof's key matches the token's cnf.jkt claim.
// Uses constant-time comparison.
func VerifyBinding(proofThumbprint, tokenJkt string) error {
	if !constantTimeEq(proofThumbprint, tokenJkt) {
		return ErrThumbprintMismatch
	}
	return nil
}

func computeThumbprint(pub *ecdsa.PublicKey) string {
	// Coordinates must be zero-padded to 32 bytes for P-256
	xBytes := make([]byte, 32)
	yBytes := make([]byte, 32)
	pub.X.FillBytes(xBytes)
	pub.Y.FillBytes(yBytes)
	x := base64.RawURLEncoding.EncodeToString(xBytes)
	y := base64.RawURLEncoding.EncodeToString(yBytes)

	// RFC 7638: canonical JSON with lexicographic order
	canonical := fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}`, x, y)

	hash := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func jwkToPublicKey(jwk *EcPublicJwk) (*ecdsa.PublicKey, error) {
	if jwk.Kty != "EC" || jwk.Crv != "P-256" {
		return nil, &ValidationError{"UNSUPPORTED_ALG", fmt.Sprintf("unsupported key: kty=%s, crv=%s", jwk.Kty, jwk.Crv)}
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, ErrInvalidKeyParams
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, ErrInvalidKeyParams
	}

	// Validate coordinate lengths - must be exactly 32 bytes for P-256
	// This is consistent with other implementations (Rust, Python, Java) and
	// ensures strict validation. RFC 7518 Section 6.2.1.2 specifies that
	// coordinates must be zero-padded to the full curve size.
	if len(xBytes) != 32 || len(yBytes) != 32 {
		return nil, &ValidationError{"INVALID_KEY_PARAMS", fmt.Sprintf("P-256 coordinates must be exactly 32 bytes: x=%d, y=%d", len(xBytes), len(yBytes))}
	}

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}, nil
}

func constantTimeEq(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
