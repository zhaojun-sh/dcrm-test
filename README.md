# dcrm-test
Test dcrm with ethereum and bitcoin.

## build and test 

Run the ethereum rinkeby testnet:

```
./geth --rinkeby --rpc console
```

Run the ethereum testnet transaction demo:
```
go run $GOPATH/src/github.com/dcrm-test/eth-tx.go
```

Run the DCRM with ethereum testnet transaction demo:
```
go run $GOPATH/src/github.com/dcrm-test/dcrm-tx-eth.go
```
