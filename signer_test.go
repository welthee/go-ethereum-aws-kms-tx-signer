package ethawskmssigner_test

import (
	"context"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/ethereum/go-ethereum/accounts/abi/bind/backends"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	ethawskmssigner "github.com/welthee/go-ethereum-aws-kms-tx-signer"
	"log"
	"math/big"
	"testing"
)

const keyId = "331c7988-c19b-4e30-8037-530389c92ac0"

const anotherEthAddr = "0xeB7eb6c156ac20a9c45beFDC95F1A13625B470b7"

func TestSigning(t *testing.T) {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String("eu-central-1"),
	})
	if err != nil {
		log.Fatalf("can not create aws session: %s", err)
	}

	kmsSvc := kms.New(sess)

	signer := ethawskmssigner.NewAwsKmsEthereumTxSigner(kmsSvc)
	transactOpts, err := signer.NewAwsKmsTransactorWithChainID(keyId, big.NewInt(1337))
	if err != nil {
		log.Fatalf("can not sign: %s", err)
	}

	alloc := make(core.GenesisAlloc)
	alloc[transactOpts.From] = core.GenesisAccount{Balance: big.NewInt(1000000000000000000)}
	blockchain := backends.NewSimulatedBackend(alloc, 100000000)
	blockchain.Commit()

	nonce, err := blockchain.PendingNonceAt(context.Background(), transactOpts.From)
	if err != nil {
		log.Fatal(err)
	}

	value := big.NewInt(1) // in wei (1 eth)
	gasLimit := uint64(21000)                // in units
	gasPrice := big.NewInt(5)      // in wei (30 gwei)

	toAddress := common.HexToAddress(anotherEthAddr)

	tx := types.NewTransaction(nonce, toAddress, value, gasLimit, gasPrice, nil)

	signedTx, err := transactOpts.Signer(transactOpts.From, tx)

	err = blockchain.SendTransaction(context.TODO(), signedTx)
	if err != nil {
		log.Fatalf("can not send tx %s", err)
	}

	blockchain.Commit()
}
