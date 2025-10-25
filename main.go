package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"log"
	"math/big"
	"net/http"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func main() {
	genKeys()
	http.HandleFunc("/.well-known/jwks.json", JWKSHandler)
	http.HandleFunc("/auth", AuthHandler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

var (
	goodPrivKey    *rsa.PrivateKey
	expiredPrivKey *rsa.PrivateKey
)

func genKeys() {
	// generate global key pair
	var err error
	goodPrivKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Error generating RSA keys: %v", err)
	}

	// Generate an expired key pair for demonstration purposes
	expiredPrivKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Error generating expired RSA keys: %v", err)
	}
}

const goodKID = "aRandomKeyID"

func AuthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var (
		signingKey *rsa.PrivateKey
		keyID      string
		exp        int64
	)

	// Default to the good key
	signingKey = goodPrivKey
	keyID = goodKID
	exp = time.Now().Add(1 * time.Hour).Unix()

	// If the expired query parameter is set, use the expired key
	if expired, _ := strconv.ParseBool(r.URL.Query().Get("expired")); expired {
		signingKey = expiredPrivKey
		keyID = "expiredKeyId"
		exp = time.Now().Add(-1 * time.Hour).Unix()
	}

	// Create the token with the expiry
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"exp": exp,
	})
	// Set the key ID header
	token.Header["kid"] = keyID
	// Sign the token with the private key
	signedToken, err := token.SignedString(signingKey)
	if err != nil {
		http.Error(w, "failed to sign token", http.StatusInternalServerError)
		return
	}

	_, _ = w.Write([]byte(signedToken))
}

type (
	JWKS struct {
		Keys []JWK `json:"keys"`
	}
	JWK struct {
		KID       string `json:"kid"`
		Algorithm string `json:"alg"`
		KeyType   string `json:"kty"`
		Use       string `json:"use"`
		N         string `json:"n"`
		E         string `json:"e"`
	}
)

func JWKSHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	base64URLEncode := func(b *big.Int) string {
		return base64.RawURLEncoding.EncodeToString(b.Bytes())
	}
	publicKey := goodPrivKey.Public().(*rsa.PublicKey)
	resp := JWKS{
		Keys: []JWK{
			{
				KID:       goodKID,
				Algorithm: "RS256",
				KeyType:   "RSA",
				Use:       "sig",
				N:         base64URLEncode(publicKey.N),
				E:         base64URLEncode(big.NewInt(int64(publicKey.E))),
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
