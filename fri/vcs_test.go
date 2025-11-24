package fri

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
)

type merkleTestVector struct {
	Root           [32]uints.U8
	ColumnLogSizes []uint8
	Queries        [][]int
	Values         []m31.M31
	HashWitness    [][32]uints.U8
}

type rawMerkleTestVector struct {
	Root           string    `json:"root"`
	ColumnLogSizes []uint8   `json:"column_log_sizes"`
	Queries        [][]int   `json:"queries"`
	Values         []uint32  `json:"values"`
	HashWitness    [][]uint8 `json:"hash_witness"`
}

var merkleFixture = mustLoadMerkleTestVector()

type merkleDecommitCircuit struct{}

func (c *merkleDecommitCircuit) Define(api frontend.API) error {
	data := merkleFixture
	columnLogSizes := append([]uint8(nil), data.ColumnLogSizes...)
	verifier := NewMerkleVerifier(api, data.Root, columnLogSizes)

	queries := append([][]int(nil), data.Queries...)
	values := append([]m31.M31(nil), data.Values...)
	hashWitness := make([][32]uints.U8, len(data.HashWitness))
	copy(hashWitness, data.HashWitness)

	decommitment := &MerkleDecommitment{
		HashWitness: hashWitness,
	}

	verifier.Verify(queries, values, decommitment)
	return nil
}

// test for merkle decommitment verification using fixture using modified stwo prover output
func TestMerkleDecommitmentVerification(t *testing.T) {
	assert := test.NewAssert(t)
	circuit := &merkleDecommitCircuit{}
	witness := &merkleDecommitCircuit{}
	assert.ProverSucceeded(circuit, witness, test.WithCurves(ecc.BN254), test.NoFuzzing(), test.NoProverChecks())
}

func mustLoadMerkleTestVector() merkleTestVector {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		panic("failed to determine caller info for merkle test vector")
	}
	rootDir := filepath.Clean(filepath.Join(filepath.Dir(filename), ".."))
	dataPath := filepath.Join(rootDir, "test_data", "decommitment_data.json")

	rawBytes, err := os.ReadFile(dataPath)
	if err != nil {
		panic(err)
	}

	var raw rawMerkleTestVector
	if err := json.Unmarshal(rawBytes, &raw); err != nil {
		panic(err)
	}

	rootBytes, err := hex.DecodeString(raw.Root)
	if err != nil {
		panic(err)
	}
	if len(rootBytes) != 32 {
		panic("invalid merkle root length")
	}

	var root [32]uints.U8
	for i, b := range rootBytes {
		root[i] = uints.NewU8(b)
	}

	queries := raw.Queries

	values := make([]m31.M31, len(raw.Values))
	for i, v := range raw.Values {
		values[i] = m31.NewM31Unchecked(v)
	}

	hashWitness := make([][32]uints.U8, len(raw.HashWitness))
	for i, entry := range raw.HashWitness {
		if len(entry) != 32 {
			panic("invalid hash witness entry length")
		}
		for j, b := range entry {
			hashWitness[i][j] = uints.NewU8(b)
		}
	}

	return merkleTestVector{
		Root:           root,
		ColumnLogSizes: append([]uint8(nil), raw.ColumnLogSizes...),
		Queries:        queries,
		Values:         values,
		HashWitness:    hashWitness,
	}
}
