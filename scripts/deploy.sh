# Don't forget the 0x prefix
from=0x71562b71999873db5b286df957af199ec94617f7

echo 'deploying contract'
curl --data "{\"jsonrpc\":\"2.0\",\"method\": \"eth_sendTransaction\", \"params\": [{\"from\": \"$from\", \"data\": \"$1\"}], \"id\": 100}" -H "Content-Type: application/json" localhost:8545
