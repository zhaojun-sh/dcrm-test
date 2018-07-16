package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"math/big"
)

const (
	KEYFILE           = `{"address":"0520e8e5e08169c4dbc1580dc9bf56638532773a","crypto":{"cipher":"aes-128-ctr","ciphertext":"12e4c5ca6e41ec2d45c518d14e658f15e3c706b609992df835978f8d6d7fe8b9","cipherparams":{"iv":"1fff146508df80aa03d2071b6aa45239"},"kdf":"scrypt","kdfparams":{"dklen":32,"n":262144,"p":1,"r":8,"salt":"680f6ebed2fb8f72179743b8a7df2696ccfeb5fe373b98f99d5df467206136f9"},"mac":"459d01e770058f8c0189b09b666bc986d81cf6afd0bf9e17b62f71958cc4be68"},"id":"8f033c61-afad-4ee4-a168-5539c99b3557","version":3}`
	SIGN_PASSPHRASE   = `qwe123`
	COINBASE_ADDR_HEX = `0x0520e8e5E08169c4dbc1580Dc9bF56638532773A`
	ALTER_ADDR_HEX    = `0xb0d21ee56ce196be7102baa202db73689f229c28`
	CHAIN_ID          = 4 //ethereum rinkeby testnet ID
)

func main() {

	// 创建账户
	fromAccDef := accounts.Account{
		Address: common.HexToAddress(COINBASE_ADDR_HEX),
	}
	toAccDef := accounts.Account{
		Address: common.HexToAddress(ALTER_ADDR_HEX),
	}
	fmt.Println("\nFrom address:\n", fromAccDef.Address.String())
	fmt.Println("\nTo address:\n", toAccDef.Address.String())

	// 建立交易 可以通过mew设置交易参数 https://www.myetherwallet.com/#offline-transaction
	tx := types.NewTransaction(
		0x09,                           // nonce
		toAccDef.Address,               // to address
		big.NewInt(0x016345785d8a0000), // amount
		0x04baf0,                       // gasLimit
		big.NewInt(41000000000),        // gasPrice
		[]byte(`data`))                 // data


	// 解析私钥文件
	keyWrapper, keyErr := keystore.DecryptKey([]byte(KEYFILE), SIGN_PASSPHRASE)
	if keyErr != nil {
		fmt.Println("key decrypt error:")
		panic(keyErr)
	}
	fmt.Printf("\nkey extracted:\n address = %s\n", keyWrapper.Address.String())

	privateKey := hex.EncodeToString(keyWrapper.PrivateKey.D.Bytes())
	fmt.Printf("\nPrivateKey:\n key = %s\n", privateKey)

	// Define signer and chain id
	chainID := big.NewInt(CHAIN_ID)
	signer := types.NewEIP155Signer(chainID)

	//用私钥签署交易签名
	signature, signatureErr := crypto.Sign(signer.Hash(tx).Bytes(), keyWrapper.PrivateKey)
	if signatureErr != nil {
		fmt.Println("signature create error:")
		panic(signatureErr)
	}
	fmt.Printf("\nsig: \n hash = %s\n", signer.Hash(tx).String())
	fmt.Printf("\n Sign = %s\n", hex.EncodeToString(signature))

	sigTx, signErr := tx.WithSignature(signer, signature)
	if signErr != nil {
		fmt.Println("signer with signature error:")
		panic(signErr)
	}
	fmt.Printf("\nTX with sig:\n RAWSign = %+v\n", sigTx)
	/*
		sigTx, sigErr := types.SignTx(tx, signer, keyWrapper.PrivateKey)
		if sigErr != nil {
			fmt.Println("signer with SignTx error:")
			panic(sigErr)
		}
	*/
	fmt.Printf("\nSignTx:\nChainId\t\t=%s\nGas\t\t=%d\nGasPrice\t=%s\nNonce\t\t=%d\nHash\t\t=%s\nData\t\t=%s\nCost\t\t=%s\n",
		sigTx.ChainId(), sigTx.Gas(), sigTx.GasPrice(), sigTx.Nonce(), sigTx.Hash().Hex(), sigTx.Data(), sigTx.Cost())

	// 本地运行geth连接测试网络发送交易: ./geth --rinkeby --rpc console
	client, err := ethclient.Dial("http://127.0.0.1:8545") // 8545=geth RPC port
	if err != nil {
		fmt.Println("client connection error:")
		panic(err)
	}
	fmt.Println("\nHTTP-RPC client connected\n")

	//发送交易到网络
	ctx := context.Background()
	txErr := client.SendTransaction(ctx, sigTx)
	if txErr != nil {
		fmt.Println("send tx error:")
		panic(txErr)
	}
	fmt.Printf("send success tx.hash=%s\n", sigTx.Hash().String())

}
