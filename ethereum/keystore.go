package ethereum

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pborman/uuid"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

const (
	keyHeaderKDF = "scrypt"

	// StandardScryptN is the N parameter of Scrypt encryption algorithm, using 256MB
	// memory and taking approximately 1s CPU time on a modern processor.
	StandardScryptN = 1 << 18

	// StandardScryptP is the P parameter of Scrypt encryption algorithm, using 256MB
	// memory and taking approximately 1s CPU time on a modern processor.
	StandardScryptP = 1

	// LightScryptN is the N parameter of Scrypt encryption algorithm, using 4MB
	// memory and taking approximately 100ms CPU time on a modern processor.
	LightScryptN = 1 << 12

	// LightScryptP is the P parameter of Scrypt encryption algorithm, using 4MB
	// memory and taking approximately 100ms CPU time on a modern processor.
	LightScryptP = 6

	scryptR     = 8
	scryptDKLen = 32

	// VeryLightScryptN VeryLightScryptN
	VeryLightScryptN = 2
	// VeryLightScryptP VeryLightScryptP
	VeryLightScryptP = 1
)

// EncryptedKeyJSONV3 EncryptedKeyJSONV3
type EncryptedKeyJSONV3 struct {
	Address string     `json:"address"`
	Crypto  cryptoJSON `json:"crypto"`
	Id      string     `json:"id"`
	Version int        `json:"version"`
}

type encryptedKeyJSONV1 struct {
	Address string     `json:"address"`
	Crypto  cryptoJSON `json:"crypto"`
	Id      string     `json:"id"`
	Version string     `json:"version"`
}

type cryptoJSON struct {
	Cipher       string                 `json:"cipher"`
	CipherText   string                 `json:"ciphertext"`
	CipherParams cipherparamsJSON       `json:"cipherparams"`
	KDF          string                 `json:"kdf"`
	KDFParams    map[string]interface{} `json:"kdfparams"`
	MAC          string                 `json:"mac"`
}

type cipherparamsJSON struct {
	IV string `json:"iv"`
}

var (
	ErrNoMatch = errors.New("no key for given address or file")
	ErrDecrypt = errors.New("could not decrypt key with given passphrase")
)

// Ks Keystore
var Ks Keystore

// Keystore Keystore
type Keystore struct {
}

// NewKey NewKey
func (ks *Keystore) NewKey() (*keystore.Key, error) {
	_key, err := ks.newKey(crand.Reader)
	return _key, err
}

// GenKeystore GenKeystore
func (ks *Keystore) GenKeystore(key *keystore.Key, passphrase string) ([]byte, error) {
	keyjson, err := keystore.EncryptKey(key, passphrase, VeryLightScryptN, VeryLightScryptP)
	return keyjson, err
}

// Update Update
func (ks *Keystore) Update(keyjson []byte, passphrase, newPassphrase string) ([]byte, error) {
	key, err := keystore.DecryptKey(keyjson, passphrase)
	if err != nil {
		return nil, err
	}

	_keyjson, err := keystore.EncryptKey(key, newPassphrase, VeryLightScryptN, VeryLightScryptP)
	return _keyjson, err
}

func (ks *Keystore) newKey(rand io.Reader) (*keystore.Key, error) {
	privateKeyECDSA, err := ecdsa.GenerateKey(crypto.S256(), rand)
	if err != nil {
		return nil, err
	}
	return ks.newKeyFromECDSA(privateKeyECDSA), nil
}

func (ks *Keystore) newKeyFromECDSA(privateKeyECDSA *ecdsa.PrivateKey) *keystore.Key {
	id := uuid.NewRandom()
	key := &keystore.Key{
		Id:         id,
		Address:    crypto.PubkeyToAddress(privateKeyECDSA.PublicKey),
		PrivateKey: privateKeyECDSA,
	}
	return key
}

// GenKeyFromECDSA GenKeyFromECDSA
func (ks *Keystore) GenKeyFromECDSA(privateKeyECDSA *ecdsa.PrivateKey) *keystore.Key {
	id := uuid.NewRandom()
	key := &keystore.Key{
		Id:         id,
		Address:    crypto.PubkeyToAddress(privateKeyECDSA.PublicKey),
		PrivateKey: privateKeyECDSA,
	}
	return key
}

// SignTx signs the given transaction with the requested account.
func (ks *Keystore) SignTx(keyjson []byte, passphrase string, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	key, err := keystore.DecryptKey(keyjson, passphrase)
	if err != nil {
		return nil, err
	}

	// Depending on the presence of the chain ID, sign with EIP155 or homestead
	if chainID != nil {
		return types.SignTx(tx, types.NewEIP155Signer(chainID), key.PrivateKey)
	}
	return types.SignTx(tx, types.HomesteadSigner{}, key.PrivateKey)
}

// CheckPassphrase CheckPassphrase
func (ks *Keystore) CheckPassphrase(keyjson []byte, passphrase string) (bool, error) {
	_, err := keystore.DecryptKey(keyjson, passphrase)
	if err != nil {
		return false, err
	}
	return true, nil
}

// DecryptKeyV3 DecryptKeyV3
func (ks *Keystore) DecryptKeyV3(keyProtected *EncryptedKeyJSONV3, auth string) ([]byte, error) {

	mac, err := hex.DecodeString(keyProtected.Crypto.MAC)
	if err != nil {
		return nil, err
	}

	// iv, err := hex.DecodeString(keyProtected.Crypto.CipherParams.IV)
	// if err != nil {
	// 	return nil, err
	// }

	cipherText, err := hex.DecodeString(keyProtected.Crypto.CipherText)
	if err != nil {
		return nil, err
	}

	derivedKey, err := getKDFKey(keyProtected.Crypto, auth)
	if err != nil {
		return nil, err
	}

	calculatedMAC := crypto.Keccak256(derivedKey[16:32], cipherText)
	if !bytes.Equal(calculatedMAC, mac) {
		return nil, ErrDecrypt
	}
	return nil, nil

	// plainText, err := aesCTRXOR(derivedKey[:16], cipherText, iv)
	// if err != nil {
	// 	return nil, err
	// }
	// return plainText, err
}

func getKDFKey(cryptoJSON cryptoJSON, auth string) ([]byte, error) {
	authArray := []byte(auth)
	salt, err := hex.DecodeString(cryptoJSON.KDFParams["salt"].(string))
	if err != nil {
		return nil, err
	}
	dkLen := ensureInt(cryptoJSON.KDFParams["dklen"])

	if cryptoJSON.KDF == keyHeaderKDF {
		n := ensureInt(cryptoJSON.KDFParams["n"])
		r := ensureInt(cryptoJSON.KDFParams["r"])
		p := ensureInt(cryptoJSON.KDFParams["p"])
		return scrypt.Key(authArray, salt, n, r, p, dkLen)

	} else if cryptoJSON.KDF == "pbkdf2" {
		c := ensureInt(cryptoJSON.KDFParams["c"])
		prf := cryptoJSON.KDFParams["prf"].(string)
		if prf != "hmac-sha256" {
			return nil, fmt.Errorf("Unsupported PBKDF2 PRF: %s", prf)
		}
		key := pbkdf2.Key(authArray, salt, c, dkLen, sha256.New)
		return key, nil
	}

	return nil, fmt.Errorf("Unsupported KDF: %s", cryptoJSON.KDF)
}

func ensureInt(x interface{}) int {
	res, ok := x.(int)
	if !ok {
		res = int(x.(float64))
	}
	return res
}

func aesCTRXOR(key, inText, iv []byte) ([]byte, error) {
	// AES-128 is selected due to size of encryptKey.
	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(aesBlock, iv)
	outText := make([]byte, len(inText))
	stream.XORKeyStream(outText, inText)
	return outText, err
}
