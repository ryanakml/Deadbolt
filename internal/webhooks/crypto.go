package webhooks

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"strconv"
	"strings"
	"time"
)

var (
	ErrInvalidCiphertext = errors.New("invalid or corrupted encrypted secret")
	ErrInvalidMasterKey  = errors.New("master encryption key must be 32 bytes (AES-256)")
	ErrSignatureExpired  = errors.New("webhook signature timestamp outside tolerance window")
	ErrSignatureMismatch = errors.New("webhook signature does not match expected HMAC")
)

// DefaultMasterKey returns the 32-byte master key configured via environment,
// or a deterministic fallback key for testing/local-dev.
func DefaultMasterKey() []byte {
	k := os.Getenv("DEADBOLT_WEBHOOK_ENCRYPTION_KEY")
	if len(k) == 64 {
		// Hex encoded 32 bytes
		if b, err := hex.DecodeString(k); err == nil && len(b) == 32 {
			return b
		}
	}
	if len(k) == 32 {
		return []byte(k)
	}
	// Deterministic fallback for dev/testing
	h := sha256.Sum256([]byte("deadbolt-default-webhook-master-key-seed"))
	return h[:]
}

// GenerateSecret generates a fresh cryptographically random webhook secret and key ID.
func GenerateSecret() (secret string, keyID string) {
	secBytes := make([]byte, 24)
	if _, err := io.ReadFull(rand.Reader, secBytes); err != nil {
		panic(err)
	}
	kidBytes := make([]byte, 4)
	if _, err := io.ReadFull(rand.Reader, kidBytes); err != nil {
		panic(err)
	}
	secret = "whsec_" + hex.EncodeToString(secBytes)
	keyID = "key_" + hex.EncodeToString(kidBytes)
	return secret, keyID
}

// EncryptSecret encrypts a plaintext webhook secret using AES-256-GCM.
func EncryptSecret(plaintext string, masterKey []byte) (string, error) {
	if len(masterKey) != 32 {
		return "", ErrInvalidMasterKey
	}
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptSecret decrypts a base64-encoded AES-256-GCM webhook secret.
func DecryptSecret(ciphertextB64 string, masterKey []byte) (string, error) {
	if len(masterKey) != 32 {
		return "", ErrInvalidMasterKey
	}
	raw, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return "", fmt.Errorf("%w: base64 decode failed", ErrInvalidCiphertext)
	}
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", fmt.Errorf("%w: ciphertext too short", ErrInvalidCiphertext)
	}
	nonce, cipherbytes := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, cipherbytes, nil)
	if err != nil {
		return "", fmt.Errorf("%w: authentication failed", ErrInvalidCiphertext)
	}
	return string(plaintext), nil
}

// SignPayload computes HMAC-SHA256 over timestamp + "." + body and returns
// both the full header string and raw hex signature.
func SignPayload(secret string, keyID string, timestamp int64, body []byte) (headerVal string, sigHex string) {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(fmt.Sprintf("%d.", timestamp)))
	mac.Write(body)
	sigHex = hex.EncodeToString(mac.Sum(nil))
	headerVal = fmt.Sprintf("t=%d,v1=%s,kid=%s", timestamp, sigHex, keyID)
	return headerVal, sigHex
}

// VerifySignature verifies that a given HMAC signature matches the payload and
// that the timestamp is within the permitted tolerance window (e.g. 5 minutes).
func VerifySignature(secret string, timestamp int64, body []byte, sigHex string, tolerance time.Duration) error {
	now := time.Now().Unix()
	diff := math.Abs(float64(now - timestamp))
	if diff > tolerance.Seconds() {
		return ErrSignatureExpired
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(fmt.Sprintf("%d.", timestamp)))
	mac.Write(body)
	expectedMAC := mac.Sum(nil)

	actualMAC, err := hex.DecodeString(sigHex)
	if err != nil {
		return fmt.Errorf("%w: signature hex invalid", ErrSignatureMismatch)
	}

	if !hmac.Equal(expectedMAC, actualMAC) {
		return ErrSignatureMismatch
	}
	return nil
}

type ParsedSignature struct {
	Timestamp int64
	Signature string
	KeyID     string
}

// ParseSignatureHeader parses the Deadbolt-Signature header formatted as t={timestamp},v1={hmac},kid={keyId}.
func ParseSignatureHeader(headerVal string) (*ParsedSignature, error) {
	parts := strings.Split(headerVal, ",")
	res := &ParsedSignature{}
	for _, part := range parts {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.TrimSpace(kv[0])
		val := strings.TrimSpace(kv[1])
		switch key {
		case "t":
			ts, err := strconv.ParseInt(val, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("%w: invalid timestamp in header: %v", ErrInvalidSignatureHeader, err)
			}
			res.Timestamp = ts
		case "v1":
			res.Signature = val
		case "kid":
			res.KeyID = val
		}
	}
	if res.Timestamp == 0 || res.Signature == "" {
		return nil, fmt.Errorf("%w: missing required signature fields", ErrInvalidSignatureHeader)
	}
	return res, nil
}

// VerifyHeader parses the signature header and verifies the signature within tolerance.
func VerifyHeader(secret string, body []byte, headerVal string, tolerance time.Duration) error {
	parsed, err := ParseSignatureHeader(headerVal)
	if err != nil {
		return err
	}
	return VerifySignature(secret, parsed.Timestamp, body, parsed.Signature, tolerance)
}
