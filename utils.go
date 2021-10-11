package ethawskmssigner

import (
	"bytes"
	"crypto/ecdsa"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pkg/errors"
)

func GetPubKey(svc *kms.KMS, keyId string) (*ecdsa.PublicKey, error) {
	pubkey := keyCache.Get(keyId)

	if pubkey == nil {
		pubKeyBytes, err := getPublicKeyDerBytesFromKMS(svc, keyId)
		if err != nil {
			return nil, err
		}

		pubkey, err = crypto.UnmarshalPubkey(pubKeyBytes)
		if err != nil {
			return nil, errors.Wrap(err, "can not construct secp256k1 public key from key bytes")
		}
		keyCache.Add(keyId, pubkey)
	}
	return pubkey, nil
}

func adjustSignatureLength(buffer []byte) []byte {
	buffer = bytes.TrimLeft(buffer, "\x00")
	for len(buffer) < 32 {
		zeroBuf := []byte{0}
		buffer = append(zeroBuf, buffer...)
	}
	return buffer
}
