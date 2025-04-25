package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	goruntime "runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	//"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/core/vm/runtime"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/triedb"
	"github.com/ethereum/go-ethereum/triedb/hashdb"
)

type submissionResult struct {
	Output         string `json:"output"`
	Allocs         string `json:"allocs"`
	Time           string `json:"time"`
	BytesAllocated string `json:"bytesAllocated"`
	GasUsed        string `json:"gasUsed"`
}

type execStatistics struct {
	Time           time.Duration `json:"time"`           // The execution Time.
	Allocs         int64         `json:"allocs"`         // The number of heap allocations during execution.
	BytesAllocated int64         `json:"bytesAllocated"` // The cumulative number of bytes allocated during execution.
	GasUsed        uint64        `json:"gasUsed"`        // the amount of gas used during execution
}

func timedExecutor(
	bench bool,
	execFunc func() ([]byte, uint64, error),
) ([]byte, execStatistics, error) {
	if bench {
		testing.Init()
		// Do one warm-up run
		output, gasUsed, err := execFunc()
		result := testing.Benchmark(func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				haveOutput, haveGasUsed, haveErr := execFunc()
				if !bytes.Equal(haveOutput, output) {
					panic(fmt.Sprintf("output differs\nhave %x\nwant %x\n", haveOutput, output))
				}
				if haveGasUsed != gasUsed {
					panic(fmt.Sprintf("gas differs, have %v want %v", haveGasUsed, gasUsed))
				}
				if haveErr != err {
					panic(fmt.Sprintf("err differs, have %v want %v", haveErr, err))
				}
			}
		})
		// Get the average execution time from the benchmarking result.
		// There are other useful stats here that could be reported.
		stats := execStatistics{
			Time:           time.Duration(result.NsPerOp()),
			Allocs:         result.AllocsPerOp(),
			BytesAllocated: result.AllocedBytesPerOp(),
			GasUsed:        gasUsed,
		}
		return output, stats, err
	}
	var memStatsBefore, memStatsAfter goruntime.MemStats
	goruntime.ReadMemStats(&memStatsBefore)
	t0 := time.Now()
	output, gasUsed, err := execFunc()
	duration := time.Since(t0)
	goruntime.ReadMemStats(&memStatsAfter)
	stats := execStatistics{
		Time:           duration,
		Allocs:         int64(memStatsAfter.Mallocs - memStatsBefore.Mallocs),
		BytesAllocated: int64(memStatsAfter.TotalAlloc - memStatsBefore.TotalAlloc),
		GasUsed:        gasUsed,
	}
	return output, stats, err
}

func runSubmission(bytecode string, input string) (error, submissionResult) {
	var (
		prestate    *state.StateDB
		chainConfig *params.ChainConfig
		sender      = common.BytesToAddress([]byte("sender"))
		receiver    = common.BytesToAddress([]byte("receiver"))
		preimages   = true
		blobHashes  []common.Hash  // TODO (MariusVanDerWijden) implement blob hashes in state tests
		blobBaseFee = new(big.Int) // TODO (MariusVanDerWijden) implement blob fee in state tests
	)
	initialGas := uint64(10000000000)
	genesisConfig := new(core.Genesis)
	genesisConfig.GasLimit = initialGas
	genesisConfig.Config = params.AllDevChainProtocolChanges

	db := rawdb.NewMemoryDatabase()
	triedb := triedb.NewDatabase(db, &triedb.Config{
		Preimages: preimages,
		HashDB:    hashdb.Defaults,
	})
	defer triedb.Close()
	genesis := genesisConfig.MustCommit(db, triedb)
	sdb := state.NewDatabase(triedb, nil)
	prestate, _ = state.New(genesis.Root(), sdb)
	chainConfig = genesisConfig.Config

	hexcode := string(bytecode)

	hexcode = strings.TrimSpace(hexcode)
	code := common.FromHex(hexcode)

	runtimeConfig := runtime.Config{
		Origin:      sender,
		State:       prestate,
		GasLimit:    initialGas,
		GasPrice:    big.NewInt(0),
		Value:       big.NewInt(0),
		Difficulty:  genesisConfig.Difficulty,
		BlockNumber: new(big.Int).SetUint64(genesisConfig.Number),
		BaseFee:     genesisConfig.BaseFee,
		BlobHashes:  blobHashes,
		BlobBaseFee: blobBaseFee,
		EVMConfig:   vm.Config{},
	}

	if chainConfig != nil {
		runtimeConfig.ChainConfig = chainConfig
	} else {
		runtimeConfig.ChainConfig = params.AllEthashProtocolChanges
	}

	hexInput := []byte(input)
	hexInput = bytes.TrimSpace(hexInput)
	finalInput := common.FromHex(string(hexInput))

	var execFunc func() ([]byte, uint64, error)
	if len(code) > 0 {
		prestate.SetCode(receiver, code)
	}
	execFunc = func() ([]byte, uint64, error) {
		// don't mutate the state!
		runtimeConfig.State = prestate.Copy()
		output, gasLeft, err := runtime.Call(receiver, finalInput, &runtimeConfig)
		return output, initialGas - gasLeft, err
	}

	output, stats, err := timedExecutor(true, execFunc)
	/* if ctx.Bool(DumpFlag.Name) {
		root, err := runtimeConfig.State.Commit(genesisConfig.Number, true, false)
		if err != nil {
			fmt.Printf("Failed to commit changes %v\n", err)
			return err
		}
		dumpdb, err := state.New(root, sdb)
		if err != nil {
			fmt.Printf("Failed to open statedb %v\n", err)
			return err
		}
		fmt.Println(string(dumpdb.Dump(nil)))
	}

	if ctx.Bool(DebugFlag.Name) {
		if logs := runtimeConfig.State.Logs(); len(logs) > 0 {
			fmt.Fprintln(os.Stderr, "### LOGS")
			writeLogs(os.Stderr, logs)
		}
	} */ /*	fmt.Fprintf(os.Stderr, `EVM gas used:    %d
		execution time:  %v
		allocations:     %d
		allocated bytes: %d
		`, stats.GasUsed, stats.Time, stats.Allocs, stats.BytesAllocated)
			} */if err != nil {
		fmt.Printf(" error: %v\n", err)
	}

	return nil, submissionResult{
		"0x" + hex.EncodeToString(output),
		strconv.FormatInt(stats.Allocs, 10),
		stats.Time.String(),
		strconv.FormatInt(stats.BytesAllocated, 10),
		strconv.FormatUint(stats.GasUsed, 10),
	}
}

/*
	func TestListener(t *testing.T) {
		_, result := runSubmission(


			"6080604052348015600e575f5ffd5b506101a58061001c5f395ff3fe608060405234801561000f575f5ffd5b5060043610610029575f3560e01c8063771602f71461002d575b5f5ffd5b610047600480360381019061004291906100a9565b61005d565b60405161005491906100f6565b60405180910390f35b5f818361006a919061013c565b905092915050565b5f5ffd5b5f819050919050565b61008881610076565b8114610092575f5ffd5b50565b5f813590506100a38161007f565b92915050565b5f5f604083850312156100bf576100be610072565b5b5f6100cc85828601610095565b92505060206100dd85828601610095565b9150509250929050565b6100f081610076565b82525050565b5f6020820190506101095f8301846100e7565b92915050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601160045260245ffd5b5f61014682610076565b915061015183610076565b92508282019050808211156101695761016861010f565b5b9291505056fea26469706673582212207021c5827aef71e66e3fc7c2210108785f4e0631ab2a0669388d1417a4fcf09264736f6c634300081d0033",
			"",
		)
		fmt.Println(result.Output)
	}
*/
type RunRequest struct {
	Bytecode string `json:"bytecode"`
	Input    string `json:"input"`
}

func runHandler(w http.ResponseWriter, r *http.Request) {
	var req RunRequest
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "cannot read request body", http.StatusBadRequest)
		return
	}

	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	req.Bytecode = strings.TrimSpace(req.Bytecode)
	req.Input = strings.TrimSpace(req.Input)

	err, result := runSubmission(req.Bytecode, req.Input)
	if err != nil {
		http.Error(w, fmt.Sprintf("execution error: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func main() {
	http.HandleFunc("/run", runHandler)
	fmt.Println("Listening on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
