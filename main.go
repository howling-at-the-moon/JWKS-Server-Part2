package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"strconv"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/golang-jwt/jwt/v5"
)

const (
	dbFile = "totally_not_my_privateKeys.db"
)

func openDB() (*sql.DB, error) {
	db, err := sql.Open("sqlite3", dbFile)
	if err != nil {
		return nil, err
	}
	const schema = `
	CREATE TABLE IF NOT EXISTS keys(
		kid INTEGER PRIMARY KEY AUTOINCREMENT,
		key BLOB NOT NULL,
		exp INTEGER NOT NULL
	);`
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

// ensureAtLeastOneExpiredAndOneValid makes sure POST:/auth can serve both cases
func ensureAtLeastOneExpiredAndOneValid(db *sql.DB) error {
	now := time.Now().Unix()

	var cntExpired, cntValid int
	if err := db.QueryRow(`SELECT COUNT(*) FROM keys WHERE exp <= ?`, now).Scan(&cntExpired); err != nil {
		return err
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM keys WHERE exp > ?`, now).Scan(&cntValid); err != nil {
		return err
	}

	if cntExpired < 1 {
		if _, err := insertNewRSAKey(db, time.Now().Add(-1*time.Minute)); err != nil {
			return err
		}
	}
	if cntValid < 1 {
		if _, err := insertNewRSAKey(db, time.Now().Add(1*time.Hour)); err != nil {
			return err
		}
	}
	return nil
}

// insertNewRSAKey generates an RSA key, PEM-encodes it, and inserts it with exp
func insertNewRSAKey(db *sql.DB, exp time.Time) (int64, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return 0, err
	}
	der := x509.MarshalPKCS1PrivateKey(priv)
	pemBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}
	pemBytes := pem.EncodeToMemory(pemBlock)

	res, err := db.Exec(`INSERT INTO keys (key, exp) VALUES (?, ?)`, pemBytes, exp.Unix())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func parseRSAPrivateKeyFromPEM(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("invalid PEM")
	}
	if pk, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return pk, nil
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		if pk, ok := keyAny.(*rsa.PrivateKey); ok {
			return pk, nil
		}
	}
	return nil, errors.New("unsupported private key format")
}

type dbKey struct {
	kid int64
	exp int64
	pem []byte
}

func getOneUnexpiredKey(db *sql.DB) (*dbKey, error) {
	now := time.Now().Unix()
	row := db.QueryRow(`SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY kid LIMIT 1`, now)
	var k dbKey
	if err := row.Scan(&k.kid, &k.pem, &k.exp); err != nil {
		return nil, err
	}
	return &k, nil
}

func getOneExpiredKey(db *sql.DB) (*dbKey, error) {
	now := time.Now().Unix()
	row := db.QueryRow(`SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY kid LIMIT 1`, now)
	var k dbKey
	if err := row.Scan(&k.kid, &k.pem, &k.exp); err != nil {
		return nil, err
	}
	return &k, nil
}

func getAllUnexpiredKeys(db *sql.DB) ([]dbKey, error) {
	now := time.Now().Unix()
	rows, err := db.Query(`SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY kid`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []dbKey
	for rows.Next() {
		var k dbKey
		if err := rows.Scan(&k.kid, &k.pem, &k.exp); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func main() {
	db, err := openDB()
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	if err := ensureAtLeastOneExpiredAndOneValid(db); err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		authHandler(db, w, r)
	})
	http.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		jwksHandler(db, w, r)
	})
	// (optional) also expose /jwks for convenience
	http.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		jwksHandler(db, w, r)
	})

	log.Println("JWKS server (DB-backed) listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func authHandler(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	wantExpired := false
	if v := r.URL.Query().Get("expired"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			wantExpired = b
		}
	}

	var k *dbKey
	var err error
	if wantExpired {
		k, err = getOneExpiredKey(db)
	} else {
		k, err = getOneUnexpiredKey(db)
	}
	if err != nil {
		http.Error(w, "no suitable key", http.StatusInternalServerError)
		return
	}

	priv, err := parseRSAPrivateKeyFromPEM(k.pem)
	if err != nil {
		http.Error(w, "bad key", http.StatusInternalServerError)
		return
	}

	exp := time.Now().Add(15 * time.Minute).Unix()
	if wantExpired {
		exp = time.Now().Add(-15 * time.Minute).Unix()
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": "userABC",
		"exp": exp,
	})
	token.Header["kid"] = fmt.Sprintf("%d", k.kid)

	signed, err := token.SignedString(priv)
	if err != nil {
		http.Error(w, "signing failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte(signed))
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

func jwksHandler(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	keys, err := getAllUnexpiredKeys(db)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}

	base64URLEncode := func(b *big.Int) string {
		return base64.RawURLEncoding.EncodeToString(b.Bytes())
	}

	resp := JWKS{Keys: make([]JWK, 0, len(keys))}
	for _, k := range keys {
		priv, err := parseRSAPrivateKeyFromPEM(k.pem)
		if err != nil {
			continue // skip malformed entries
		}
		pub := &priv.PublicKey
		resp.Keys = append(resp.Keys, JWK{
			KID:       fmt.Sprintf("%d", k.kid),
			Algorithm: "RS256",
			KeyType:   "RSA",
			Use:       "sig",
			N:         base64URLEncode(pub.N),
			E:         base64URLEncode(big.NewInt(int64(pub.E))),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
