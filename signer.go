package ethawskmssigner

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pkg/errors"
	"math/big"
)

const messageTypeDigest = "DIGEST"
const signingAlgorithm = "ECDSA_SHA_256"

var secp256k1N = elliptic.P256().Params().N
var halfSecp256k1N = new(big.Int).Div(secp256k1N, big.NewInt(2))

type AwsKmsEthereumTxSigner struct {
	svc         *kms.KMS
	pubKeyCache *pubKeyCache
}

func NewAwsKmsEthereumTxSigner(svc *kms.KMS) *AwsKmsEthereumTxSigner {
	return &AwsKmsEthereumTxSigner{
		svc:         svc,
		pubKeyCache: newPubKeyCache(),
	}
}

type asn1EcPublicKey struct {
	EcPublicKeyInfo asn1EcPublicKeyInfo
	PublicKey       asn1.BitString
}

type asn1EcPublicKeyInfo struct {
	Oid1 asn1.ObjectIdentifier
	Oid2 asn1.ObjectIdentifier
}

type asn1EcSig struct {
	R asn1.RawValue
	S asn1.RawValue
}

func (s *AwsKmsEthereumTxSigner) NewAwsKmsTransactorWithChainID(keyId string, chainID *big.Int) (*bind.TransactOpts,
	error) {
	var ecdsaPublicKey *ecdsa.PublicKey
	cachedKey := s.pubKeyCache.Get(keyId)

	if cachedKey == nil {
		getPubKeyOutput, err := s.svc.GetPublicKey(&kms.GetPublicKeyInput{
			KeyId: aws.String(keyId),
		})
		if err != nil {
			return nil, errors.Wrapf(err, "can not get public key for KeyId=%s", keyId)
		}

		var pub asn1EcPublicKey
		_, err = asn1.Unmarshal(getPubKeyOutput.PublicKey, &pub)
		if err != nil {
			return nil, errors.Wrapf(err, "can not parse asn1 public key for KeyId=%s", keyId)
		}

		cachedKey, err = crypto.UnmarshalPubkey(pub.PublicKey.Bytes)
		if err != nil {
			return nil, errors.Wrap(err, "can not construct secp256k1 public key from key bytes")
		}

		s.pubKeyCache.Add(keyId, cachedKey)
	}

	ecdsaPublicKey, ok := cachedKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.Errorf("key with keyId=%s must be of type ECDSA and on curve secp256k1", keyId)
	}

	keyAddr := crypto.PubkeyToAddress(*ecdsaPublicKey)
	if chainID == nil {
		return nil, bind.ErrNoChainID
	}

	fmt.Printf("key addr=%s\n", keyAddr.Hex())

	signer := types.LatestSignerForChainID(chainID)
	return &bind.TransactOpts{
		From: keyAddr,
		Signer: func(address common.Address, tx *types.Transaction) (*types.Transaction, error) {
			if address != keyAddr {
				return nil, bind.ErrNotAuthorized
			}

			signInput := &kms.SignInput{
				KeyId:            aws.String(keyId),
				SigningAlgorithm: aws.String(signingAlgorithm),
				MessageType:      aws.String(messageTypeDigest),
				Message:          tx.Hash().Bytes(),
			}

			signOutput, err := s.svc.Sign(signInput)
			if err != nil {
				return nil, err
			}

			fmt.Printf("Sigbytes in hex=%s\n", hex.EncodeToString(signOutput.Signature))

			var sigAsn1 asn1EcSig
			_, err = asn1.Unmarshal(signOutput.Signature, &sigAsn1)
			if err != nil {
				return nil, err
			}

			rBytes := bytes.Trim(sigAsn1.R.Bytes, "\x00")
			sBytes := bytes.Trim(sigAsn1.S.Bytes, "\x00")
			vBytes := []byte{0x00} // TODO how to calculate this?

			fmt.Printf("r=%s s=%s\n", hex.EncodeToString(rBytes), hex.EncodeToString(sBytes))

			sBigInt := new(big.Int).SetBytes(sigAsn1.S.Bytes)

			if sBigInt.Cmp(halfSecp256k1N) > 0 {
				sBytes = new(big.Int).Sub(secp256k1N, sBigInt).Bytes()
			}

			fmt.Printf("len(r)=%d len(s)=%d\n", len(rBytes), len(sBytes))

			signature := append(rBytes, sBytes...)
			signature = append(signature, vBytes...)

			return tx.WithSignature(signer, signature)
		},
	}, nil
}
