# Don't forget the 0x prefix

echo 'getting receipt'
curl --data "{\"jsonrpc\":\"2.0\",\"method\": \"eth_getTransactionReceipt\", \"params\": [\"$1\"], \"id\": 7}" -H "Content-Type: application/json" localhost:8545
