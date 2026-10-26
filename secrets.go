package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

var ErrMasterPassword = errors.New("thunderbird profile is protected by a master password; credential decryption is not supported")

type Credentials struct {
	oauth          []oauthLogin
	oauthMu        sync.Mutex
	oauthCache     map[int]*oauthToken
	oauthTransport http.RoundTripper // internal test seam; endpoints are never configurable
	oauthNow       func() time.Time
	byHostUser     map[string]string // "host\x00user" -> password
}

func credKey(host, user string) string { return host + "\x00" + user }

func (c *Credentials) Lookup(host, user string) (string, bool) {
	if c == nil {
		return "", false
	}
	pw, ok := c.byHostUser[credKey(host, user)]
	return pw, ok
}

// ---- ASN.1 shapes ----

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}
type encryptedItem struct { // outer: { AlgorithmIdentifier, OCTET STRING }
	Algo   algorithmIdentifier
	Cipher []byte
}
type pbeParam3DES struct { // legacy params: { salt, iterations }
	EntrySalt  []byte
	Iterations int
}
type pbkdf2Params struct {
	EntrySalt  []byte
	Iterations int
	KeyLength  int                 `asn1:"optional"`
	Prf        algorithmIdentifier `asn1:"optional"`
}
type pbes2Params struct {
	KeyDerivation algorithmIdentifier // PBKDF2 + params
	Encryption    algorithmIdentifier // aes256-CBC + IV OCTET STRING
}
type loginASN1 struct { // logins.json entry: { keyID, {algorithm OID, IV}, cipher }
	KeyID  []byte
	Algo   algorithmIdentifier
	Cipher []byte
}

var (
	oidPBES2            = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2           = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oid3DESLegacy       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 5, 1, 3}
	oidLogin3DES        = asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 7}
	oidLoginAES256      = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	oidPBKDF2HMACSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
)

func pkcs7Unpad(b []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 {
		return nil, errors.New("invalid padding block size")
	}
	if len(b) == 0 || len(b)%blockSize != 0 {
		return nil, fmt.Errorf("invalid padded length %d", len(b))
	}
	n := int(b[len(b)-1])
	if n == 0 || n > blockSize || n > len(b) {
		return nil, fmt.Errorf("invalid padding byte %d", n)
	}
	for _, c := range b[len(b)-n:] {
		if int(c) != n {
			return nil, errors.New("invalid padding")
		}
	}
	return b[:len(b)-n], nil
}

func deriveKeyPBES2(globalSalt, entrySalt []byte, iterations int) []byte {
	h := sha1.New()
	h.Write(globalSalt) // empty master password => nothing else appended
	pw := h.Sum(nil)    // 20 bytes
	return pbkdf2.Key(pw, entrySalt, iterations, 32, sha256.New)
}

func aesCBCDecrypt(key, iv, ct []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("aes-256: invalid key length %d", len(key))
	}
	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("aes-256: invalid IV length %d", len(iv))
	}
	if len(ct) == 0 || len(ct)%aes.BlockSize != 0 {
		return nil, errors.New("aes-256: ciphertext must be a non-empty multiple of block size")
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(ct)%blk.BlockSize() != 0 {
		return nil, errors.New("aes: ciphertext not a multiple of block size")
	}
	out := make([]byte, len(ct))
	cipher.NewCBCDecrypter(blk, iv).CryptBlocks(out, ct)
	return out, nil
}

func des3CBCDecrypt(key, iv, ct []byte) ([]byte, error) {
	if len(key) != 24 {
		return nil, fmt.Errorf("3des: invalid key length %d", len(key))
	}
	if len(iv) != des.BlockSize {
		return nil, fmt.Errorf("3des: invalid IV length %d", len(iv))
	}
	if len(ct) == 0 || len(ct)%des.BlockSize != 0 {
		return nil, errors.New("3des: ciphertext must be a non-empty multiple of block size")
	}
	blk, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	if len(ct)%blk.BlockSize() != 0 {
		return nil, errors.New("3des: ciphertext not a multiple of block size")
	}
	out := make([]byte, len(ct))
	cipher.NewCBCDecrypter(blk, iv).CryptBlocks(out, ct)
	return out, nil
}

// decryptPBEItem unwraps an outer {AlgorithmIdentifier, cipher} and returns the
// decrypted plaintext (still padded) using the recovered-or-derived key path.
func decryptPBEItem(globalSalt, raw []byte) ([]byte, error) {
	var item encryptedItem
	if _, err := asn1.Unmarshal(raw, &item); err != nil {
		return nil, err
	}
	switch {
	case item.Algo.Algorithm.Equal(oidPBES2):
		var p pbes2Params
		if _, err := asn1.Unmarshal(item.Algo.Parameters.FullBytes, &p); err != nil {
			return nil, err
		}
		if !p.KeyDerivation.Algorithm.Equal(oidPBKDF2) {
			return nil, fmt.Errorf("unsupported PBES2 key derivation algorithm %v", p.KeyDerivation.Algorithm)
		}
		var kdf pbkdf2Params
		if _, err := asn1.Unmarshal(p.KeyDerivation.Parameters.FullBytes, &kdf); err != nil {
			return nil, err
		}
		if !p.Encryption.Algorithm.Equal(oidLoginAES256) {
			return nil, fmt.Errorf("unsupported PBES2 cipher algorithm %v", p.Encryption.Algorithm)
		}
		if kdf.Iterations <= 0 || (kdf.KeyLength != 0 && kdf.KeyLength != 32) {
			return nil, errors.New("invalid PBKDF2 parameters")
		}
		if len(kdf.Prf.Algorithm) != 0 && !kdf.Prf.Algorithm.Equal(oidPBKDF2HMACSHA256) {
			return nil, fmt.Errorf("unsupported PBKDF2 PRF %v", kdf.Prf.Algorithm)
		}
		var iv14 []byte
		if _, err := asn1.Unmarshal(p.Encryption.Parameters.FullBytes, &iv14); err != nil {
			return nil, err
		}
		key := deriveKeyPBES2(globalSalt, kdf.EntrySalt, kdf.Iterations)
		iv := append([]byte{0x04, 0x0e}, iv14...) // NSS prefixes DER tag+len to make 16 bytes
		return aesCBCDecrypt(key, iv, item.Cipher)
	case item.Algo.Algorithm.Equal(oid3DESLegacy):
		var pp pbeParam3DES
		if _, err := asn1.Unmarshal(item.Algo.Parameters.FullBytes, &pp); err != nil {
			return nil, err
		}
		key, iv := legacy3DESKeyIV(globalSalt, pp.EntrySalt)
		return des3CBCDecrypt(key, iv, item.Cipher)
	default:
		return nil, fmt.Errorf("unsupported PBE algorithm %v", item.Algo.Algorithm)
	}
}

// legacy3DESKeyIV implements the PKCS#12 SHA1/HMAC derivation (firepwd decrypt3DES).
func legacy3DESKeyIV(globalSalt, entrySalt []byte) (key, iv []byte) {
	hp := sha1.Sum(append([]byte{}, globalSalt...))
	pes := make([]byte, 20)
	copy(pes, entrySalt)
	chpArr := sha1.Sum(append(append([]byte{}, hp[:]...), entrySalt...))
	chp := chpArr[:]
	k1 := hmacSHA1(chp, append(append([]byte{}, pes...), entrySalt...))
	tk := hmacSHA1(chp, pes)
	k2 := hmacSHA1(chp, append(append([]byte{}, tk...), entrySalt...))
	k := append(append([]byte{}, k1...), k2...) // 40 bytes
	return k[:24], k[len(k)-8:]
}

// recoverMasterKey preserves the legacy single-key lookup used by old profiles.
func recoverMasterKey(key4Path string) ([]byte, error) {
	return recoverKey4Secret(key4Path, nil, 24)
}

// recoverKey4Secret verifies the key4.db password check, selects the wrapped
// SDR key by CKA_ID when supplied, and returns its expected key bytes. NSS
// stores the per-login key ID in logins.json and in nssPrivate.a102; selecting
// the matching row is required because a profile can contain both legacy
// 3DES and newer AES keys during migration.
func recoverKey4Secret(key4Path string, keyID []byte, keyLen int) ([]byte, error) {
	if keyLen != 24 && keyLen != 32 {
		return nil, fmt.Errorf("unsupported SDR key length %d", keyLen)
	}
	// Through dbSource, not a bare immutable=1 connection. key4.db is a
	// rollback-journal database, and immutable=1 tells SQLite to skip recovery
	// entirely: against a hot journal it hands back pre-commit page images with
	// no error at all, which for a credential store means silently wrong key
	// material rather than a clean failure. dbSource reads the live file, falls
	// back to a private snapshot when NSS holds a lock, and lets that snapshot's
	// read-write connection actually run the rollback.
	db, err := openDBSource(key4Path, "key4")
	if err != nil {
		return nil, err
	}
	defer db.Close()

	var globalSalt, item2 []byte
	err = db.queryOne(`SELECT item1, item2 FROM metaData WHERE id = 'password'`, &globalSalt, &item2)
	if err != nil {
		return nil, fmt.Errorf("reading metaData: %w", err)
	}
	check, err := decryptPBEItem(globalSalt, item2)
	if err == nil {
		var blockSize int
		blockSize, err = blockSizeFor(item2)
		if err == nil {
			check, err = pkcs7Unpad(check, blockSize)
		}
	}
	if err != nil || !bytes.Equal(check, []byte("password-check")) {
		return nil, ErrMasterPassword
	}

	var a11 []byte
	if len(keyID) == 0 {
		err = db.queryOne(`SELECT a11 FROM nssPrivate WHERE a11 IS NOT NULL LIMIT 1`, &a11)
	} else {
		rows, queryErr := db.Query(`SELECT a11 FROM nssPrivate WHERE a102 = ? AND a11 IS NOT NULL LIMIT 1`, keyID)
		if queryErr != nil {
			err = queryErr
		} else {
			defer rows.Close()
			if !rows.Next() {
				if rows.Err() != nil {
					err = rows.Err()
				} else {
					err = fmt.Errorf("no NSS key matches login KeyID")
				}
			} else {
				err = rows.Scan(&a11)
			}
		}
	}
	if err != nil {
		return nil, fmt.Errorf("reading nssPrivate: %w", err)
	}
	dec, err := decryptPBEItem(globalSalt, a11)
	if err != nil {
		return nil, err
	}
	// NSS stores the SDR key bytes at the end of the unpadded key blob. Take the
	// key length implied by the login cipher (24 bytes for 3DES, 32 for AES-256).
	blockSize, err := blockSizeFor(a11)
	if err != nil {
		return nil, err
	}
	dec, err = pkcs7Unpad(dec, blockSize)
	if err != nil {
		return nil, err
	}
	if len(dec) < keyLen {
		return nil, fmt.Errorf("NSS key material too short: need %d bytes, got %d", keyLen, len(dec))
	}
	return append([]byte(nil), dec[len(dec)-keyLen:]...), nil
}

func blockSizeFor(raw []byte) (int, error) {
	var item encryptedItem
	if rest, err := asn1.Unmarshal(raw, &item); err != nil || len(rest) != 0 {
		if err == nil {
			err = errors.New("trailing ASN.1 data")
		}
		return 0, fmt.Errorf("invalid encrypted item: %w", err)
	}
	switch {
	case item.Algo.Algorithm.Equal(oidPBES2):
		var p pbes2Params
		if _, err := asn1.Unmarshal(item.Algo.Parameters.FullBytes, &p); err != nil {
			return 0, err
		}
		if !p.Encryption.Algorithm.Equal(oidLoginAES256) {
			return 0, fmt.Errorf("unsupported PBES2 cipher algorithm %v", p.Encryption.Algorithm)
		}
		return aes.BlockSize, nil
	case item.Algo.Algorithm.Equal(oid3DESLegacy):
		return des.BlockSize, nil
	default:
		return 0, fmt.Errorf("unsupported PBE algorithm %v", item.Algo.Algorithm)
	}
}

// LoadCredentials decrypts logins.json into a host/user -> password map.
func LoadCredentials(profileDir string) (*Credentials, error) {
	data, err := os.ReadFile(filepath.Join(profileDir, "logins.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return &Credentials{byHostUser: map[string]string{}}, nil
		}
		return nil, err
	}
	var file struct {
		Logins []struct {
			Hostname          string `json:"hostname"`
			HTTPRealm         string `json:"httpRealm"`
			EncryptedUsername string `json:"encryptedUsername"`
			EncryptedPassword string `json:"encryptedPassword"`
		} `json:"logins"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, err
	}
	creds := &Credentials{byHostUser: map[string]string{}}
	keyCache := map[string][]byte{}
	key4Path := filepath.Join(profileDir, "key4.db")
	for _, l := range file.Logins {
		user, err1 := decryptLoginFromProfile(key4Path, l.EncryptedUsername, keyCache)
		pass, err2 := decryptLoginFromProfile(key4Path, l.EncryptedPassword, keyCache)
		if err1 != nil || err2 != nil {
			if err1 != nil {
				return nil, fmt.Errorf("decrypting stored login: %w", err1)
			}
			return nil, fmt.Errorf("decrypting stored login: %w", err2)
		}
		if strings.HasPrefix(l.Hostname, "oauth:") {
			creds.oauth = append(creds.oauth, oauthLogin{Origin: l.Hostname, Username: user, Realm: l.HTTPRealm, RefreshToken: pass})
			continue
		}
		host := hostOnly(l.Hostname) // "imap://imap.example.com" -> "imap.example.com"
		creds.byHostUser[credKey(host, user)] = pass
	}
	return creds, nil
}

func decryptLogin(masterKey []byte, b64 string) (string, error) {
	login, iv, err := parseLogin(b64)
	if err != nil {
		return "", err
	}
	return decryptLoginRecord(masterKey, login, iv)
}

func decryptLoginFromProfile(key4Path, b64 string, keyCache map[string][]byte) (string, error) {
	login, iv, err := parseLogin(b64)
	if err != nil {
		return "", err
	}
	keyLen, _, err := loginAlgorithmSizes(login.Algo.Algorithm)
	if err != nil {
		return "", err
	}
	cacheKey := login.Algo.Algorithm.String() + ":" + string(login.KeyID)
	key, ok := keyCache[cacheKey]
	if !ok {
		key, err = recoverKey4Secret(key4Path, login.KeyID, keyLen)
		if err != nil {
			return "", err
		}
		keyCache[cacheKey] = key
	}
	return decryptLoginRecord(key, login, iv)
}

func parseLogin(b64 string) (loginASN1, []byte, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return loginASN1{}, nil, err
	}
	var l loginASN1
	rest, err := asn1.Unmarshal(raw, &l)
	if err != nil {
		return loginASN1{}, nil, err
	}
	if len(rest) != 0 {
		return loginASN1{}, nil, errors.New("trailing ASN.1 data in login")
	}
	var iv []byte
	if _, err := asn1.Unmarshal(l.Algo.Parameters.FullBytes, &iv); err != nil {
		return loginASN1{}, nil, err
	}
	return l, iv, nil
}

func loginAlgorithmSizes(oid asn1.ObjectIdentifier) (keyLen, blockSize int, err error) {
	switch {
	case oid.Equal(oidLoginAES256):
		return 32, aes.BlockSize, nil
	case oid.Equal(oidLogin3DES):
		return 24, des.BlockSize, nil
	default:
		return 0, 0, fmt.Errorf("unsupported login encryption algorithm %v", oid)
	}
}

func decryptLoginRecord(key []byte, login loginASN1, iv []byte) (string, error) {
	_, blockSize, err := loginAlgorithmSizes(login.Algo.Algorithm)
	if err != nil {
		return "", err
	}
	var pt []byte
	switch {
	case login.Algo.Algorithm.Equal(oidLoginAES256):
		pt, err = aesCBCDecrypt(key, iv, login.Cipher)
	case login.Algo.Algorithm.Equal(oidLogin3DES):
		pt, err = des3CBCDecrypt(key, iv, login.Cipher)
	}
	if err != nil {
		return "", err
	}
	pt, err = pkcs7Unpad(pt, blockSize)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

func hostOnly(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		return u.Host
	}
	return raw
}

func hmacSHA1(key, msg []byte) []byte {
	m := hmac.New(sha1.New, key)
	m.Write(msg)
	return m.Sum(nil)
}
