package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"math/big"
)

const (
	KEYFILE         = `{"address":"0520e8e5e08169c4dbc1580dc9bf56638532773a","crypto":{"cipher":"aes-128-ctr","ciphertext":"12e4c5ca6e41ec2d45c518d14e658f15e3c706b609992df835978f8d6d7fe8b9","cipherparams":{"iv":"1fff146508df80aa03d2071b6aa45239"},"kdf":"scrypt","kdfparams":{"dklen":32,"n":262144,"p":1,"r":8,"salt":"680f6ebed2fb8f72179743b8a7df2696ccfeb5fe373b98f99d5df467206136f9"},"mac":"459d01e770058f8c0189b09b666bc986d81cf6afd0bf9e17b62f71958cc4be68"},"id":"8f033c61-afad-4ee4-a168-5539c99b3557","version":3}`
	SIGN_PASSPHRASE = `qwe123`
	//	COINBASE_ADDR_HEX = `0x0520e8e5E08169c4dbc1580Dc9bF56638532773A`
	ALTER_ADDR_HEX = `0xb0d21ee56ce196be7102baa202db73689f229c28`
	CHAIN_ID       = 4 //ethereum rinkeby testnet ID
)

func main() {

	// 创建账户
	//	fromAccDef := accounts.Account{
	//		Address: common.HexToAddress(COINBASE_ADDR_HEX),
	//	}
	toAccDef := accounts.Account{
		Address: common.HexToAddress(ALTER_ADDR_HEX),
	}
	//	fmt.Println("\nFrom address:\n", fromAccDef.Address.String())
	fmt.Println("\nTo address:\n", toAccDef.Address.String())

	// 得到DCRM地址
	//pKey := "8d4c8eb0f07021ccb97dbf6714287dd119de14ba0e4c86434ae134f71343a565af989766080c392f38087d5438987d1fb2b31f50c4a47e9f232ccce5735355af"
	pKey := "2aae10e8660dda55e2233635a5e6c7be0b0ceca09390a236780d1410a1c26832392dde8f25232daa392ab312cac5c17c6bddebdc569d1a9253e585d373f97096"
	//address := crypto.PubkeyToAddress(publicKey).Hex()

	address := common.BytesToAddress(crypto.Keccak256([]byte(pKey)[12:])).Hex()

	fmt.Println("\nDCRM publicKey:\n    ", pKey)
	fmt.Println("\nDCRM address:\n    ", address)

	/*
		// 解析私钥文件
		keyWrapper, keyErr := keystore.DecryptKey([]byte(KEYFILE), SIGN_PASSPHRASE)
		if keyErr != nil {
			fmt.Println("key decrypt error:")
			panic(keyErr)
		}
		fmt.Printf("\nkey extracted:\n address=%s\n", keyWrapper.Address.String())

		privateKey := hex.EncodeToString(keyWrapper.PrivateKey.D.Bytes())
		fmt.Printf("\nPrivateKey:\n key=%s\n", privateKey)
	*/

	// 建立交易
	tx := types.NewTransaction(
		0x00,                           // nonce
		toAccDef.Address,               // to address
		big.NewInt(0x016345785d8a0000), // amount
		0x04baf0,                       // gasLimit
		big.NewInt(41000000000),        // gasPrice
		[]byte(`data`))                 // data

	// Define signer and chain id
	chainID := big.NewInt(CHAIN_ID)
	signer := types.NewEIP155Signer(chainID)
	//signer := types.HomesteadSigner{}

	//用私钥签署交易签名
	/*	   signature, signatureErr := crypto.Sign(tx.Hash().Bytes(), keyWrapper.PrivateKey)
	  if signatureErr != nil {
	     fmt.Println("signature create error:")
	     panic(signatureErr)
	}
	*/

	//获取交易hash值，用于DCRM分布式签名输入
	fmt.Printf("\nTXhash = %s\n", signer.Hash(tx).String())

	//分布式签名后的结果
	fmt.Printf("\nsig: \nR = %s\n", "2A0B3F6D9F9DBACCAA093F1DCFD8AB3F08A532ACFA847FE2BC6D9B17ABBAA39E")
	fmt.Printf("\nsig: \nS = %s\n", "C0A8156D0176F4BDBF9A9D0C95A55479A12ECB35E7EE8883164A679DBEE5112A")

	//签名结构为 R || S || V   V=0x00
	const signature = "2A0B3F6D9F9DBACCAA093F1DCFD8AB3F08A532ACFA847FE2BC6D9B17ABBAA39EC0A8156D0176F4BDBF9A9D0C95A55479A12ECB35E7EE8883164A679DBEE5112A00"
	fmt.Printf("\nSign = %s\n", signature)

	//附加签名结果至交易数据结构
	message, err := hex.DecodeString(signature)
	sigTx, signErr := tx.WithSignature(signer, message)
	if signErr != nil {
		fmt.Println("signer with signature error:")
		panic(signErr)
	}
	fmt.Printf("\nTX with sig:\n RAWSign = %s\n", sigTx)
	fmt.Printf("\nSignTx:\nChainId\t\t=%s\nGas\t\t=%d\nGasPrice\t=%s\nNonce\t\t=%d\nHash\t\t=%s\nData\t\t=%s\nCost\t\t=%s\n",
		sigTx.ChainId(), sigTx.Gas(), sigTx.GasPrice(), sigTx.Nonce(), sigTx.Hash().Hex(), sigTx.Data(), sigTx.Cost())

	// 本地运行geth连接测试网络发送交易: ./geth --rinkeby --rpc console
	client, err := ethclient.Dial("http://127.0.0.1:8545") // 8545=geth RPC port
	if err != nil {
		fmt.Println("client connection error:")
		panic(err)
	}
	fmt.Println("\nHTTP-RPC client connected")
	fmt.Println()

	ctx := context.Background()

	//getBalErr := client.BalanceAt(ctx, keyWrapper.Address, nil)
	//fmt.Printf("networkID=%s\n", client.NetworkID(context.Background()))

	//发送交易到网络
	txErr := client.SendTransaction(ctx, sigTx)
	if txErr != nil {
		fmt.Println("send tx error:")
		panic(txErr)
	}
	fmt.Printf("send success tx.hash = %s\n", sigTx.Hash().String())

}
