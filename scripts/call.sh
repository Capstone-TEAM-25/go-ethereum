# Don't forget the 0x prefix
from=0x71562b71999873db5b286df957af199ec94617f7

echo 'calling contract'
curl --data "{\"jsonrpc\":\"2.0\",\"method\": \"eth_call\", \"params\": [{\"to\": \"$1\", \"data\": \"$2\"}], \"id\": 8}" -H "Content-Type: application/json" localhost:8545
# curl --data "{\"jsonrpc\":\"2.0\",\"method\": \"eth_sendTransaction\", \"params\": [{\"from\": \"$from\", \"to\": \"$1\", \"data\": \"$2\", \"gas\": \"0x6666\"}], \"id\": 100}" -H "Content-Type: application/json" localhost:8545
