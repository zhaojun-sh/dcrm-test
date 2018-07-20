// Copyright 2018 The FUSION Foundation Authors
// This file is part of the fusion-dcrm library.
//
// The fusion-dcrm library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

// Package main implements the DCRM transaction.
package main

import (
	"encoding/hex"
	"fmt"
	"context"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/ethclient"
	"math/big"
)

const (
	ALTER_ADDR_HEX = `0xd92c6581cb000367c10a1997070ccd870287f2da`
	CHAIN_ID       = 4 //ethereum mainnet=1 rinkeby testnet=4
)

func main() {

	// Set receive address
	toAccDef := accounts.Account{
		Address: common.HexToAddress(ALTER_ADDR_HEX),
	}
	fmt.Println("\nTo address:\n", toAccDef.Address.String())

	// New transaction
	tx := types.NewTransaction(
		0x00,                           // nonce
		toAccDef.Address,               // receive address
		big.NewInt(123456789000000000), // amount
		48000, 							// gasLimit
		big.NewInt(41000000000), 		// gasPrice
		[]byte(`Powered by FUSION DCRM: The world's first decentralized signature transaction. https://github.com/FUSIONFoundation/dcrm`)) // data

	// Set chainID
	chainID := big.NewInt(CHAIN_ID)
	signer := types.NewEIP155Signer(chainID)

	// Get TXhash for DCRM sign
	fmt.Printf("\nTXhash = %s\n", signer.Hash(tx).String())

	// Signature struct: R || S || V
	const signature = "3647f23d3a6d8407862336e8536dcb8276facf7c5a69749b44dc65d2e467c2fe64894b2469992357e3dbfcdc64ab5c31983a97531dbdb5a54787f49cb777ecb601"
	fmt.Printf("\nSign = %s\n", signature)

	// With signature to TX
	message, merr := hex.DecodeString(signature)
	if merr != nil {
		fmt.Println("Decode signature error:")
		panic(merr)
	}
	sigTx, signErr := tx.WithSignature(signer, message)
	if signErr != nil {
		fmt.Println("signer with signature error:")
		panic(signErr)
	}

	// Recover publickey
	recoverpkey, perr := crypto.Ecrecover(signer.Hash(tx).Bytes(), message)
	if perr != nil {
		fmt.Println("recover signature error:")
		panic(perr)
	}
	fmt.Printf("\nrecover publickey = %s\n", hex.EncodeToString(recoverpkey))

	// Recover address, transfer test eth to this address
	recoveraddress := common.BytesToAddress(crypto.Keccak256(recoverpkey[1:])[12:]).Hex()
	fmt.Printf("\nrecover address = %s\n", recoveraddress)

	fmt.Printf("\nSignTx:\nChainId\t\t=%s\nGas\t\t=%d\nGasPrice\t=%s\nNonce\t\t=%d\nHash\t\t=%s\nData\t\t=%s\nCost\t\t=%s\n",
		sigTx.ChainId(), sigTx.Gas(), sigTx.GasPrice(), sigTx.Nonce(), sigTx.Hash().Hex(), sigTx.Data(), sigTx.Cost())

	// Get the RawTransaction
	txdata, txerr := rlp.EncodeToBytes(sigTx)
	if txerr != nil {
		panic(txerr)
	}
	fmt.Printf("\nTX with sig:\n RawTransaction = %+v\n\n", common.ToHex(txdata))

	// Connect geth RPC port: ./geth --rinkeby --rpc console
	client, err := ethclient.Dial("http://127.0.0.1:8545")
	if err != nil {
		fmt.Println("client connection error:")
		panic(err)
	}
	fmt.Println("\nHTTP-RPC client connected")
	fmt.Println()

	// Send RawTransaction to ethereum network
	ctx := context.Background()
	txErr := client.SendTransaction(ctx, sigTx)
	if txErr != nil {
		fmt.Println("send tx error:")
		panic(txErr)
	}
	fmt.Printf("send success tx.hash = %s\n", sigTx.Hash().String())
}
