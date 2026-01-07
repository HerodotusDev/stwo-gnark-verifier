package fri

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/HerodotusDev/stwo-gnark-verifier/utils"
	"github.com/HerodotusDev/stwo-gnark-verifier/variables"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
)

type merkleTestVector struct {
	Root               [32]uints.U8        `gnark:",public"`
	ColumnLogSizes     []frontend.Variable `gnark:",public"`
	Values             []m31.M31           `gnark:",public"`
	HashWitness        [][32]uints.U8      `gnark:",public"`
	BaseLayerQueries   []frontend.Variable `gnark:",public"`
	NColumnsPerLogSize []int
	QueriesShape       []int
	QueriesBranching   [][]uint8
	MaxLogSize         uint8
}

type rawMerkleTestVector struct {
	Root           string    `json:"root"`
	ColumnLogSizes []uint8   `json:"column_log_sizes"`
	Queries        [][]int   `json:"queries"`
	Values         []uint32  `json:"values"`
	HashWitness    [][]uint8 `json:"hash_witness"`
}

var data = mustLoadMerkleTestVector()

type merkleDecommitCircuit struct{}

func (c *merkleDecommitCircuit) Define(api frontend.API) error {
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		panic(err)
	}

	verifier := NewMerkleVerifier(api, uapi, data.Root, data.ColumnLogSizes, data.NColumnsPerLogSize)

	// Generate queries
	queries := utils.GenerateQueries(api, data.BaseLayerQueries, 10, data.QueriesShape, data.MaxLogSize)
	queriesLookup := utils.ToLookupTable(api, queries)

	decommitment := variables.MerkleDecommitment{
		HashWitness: data.HashWitness,
	}

	verifier.Verify(queriesLookup, data.Values, decommitment, data.QueriesShape, data.QueriesBranching)
	return nil
}

// test for merkle decommitment verification using the first decommitment of the all_components_proof.json fixture
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

	columnLogSizes := make([]frontend.Variable, len(raw.ColumnLogSizes))
	for i, logSize := range raw.ColumnLogSizes {
		columnLogSizes[i] = frontend.Variable(logSize)
	}

	if len(raw.Queries) == 0 {
		panic("merkle queries must not be empty")
	}
	maxLogSize := len(raw.Queries) - 1
	baseLayerQueries := make([]frontend.Variable, len(raw.Queries[maxLogSize]))
	for i, query := range raw.Queries[maxLogSize] {
		baseLayerQueries[i] = frontend.Variable(query)
	}
	queriesShape := make([]int, maxLogSize+1)
	queriesByLayer := make([][]int, maxLogSize+1)
	currentLayer := append([]int(nil), raw.Queries[maxLogSize]...)

	intSlicesEqual := func(a, b []int) bool {
		if len(a) != len(b) {
			return false
		}
		for i := range a {
			if a[i] != b[i] {
				return false
			}
		}
		return true
	}

	for layer := maxLogSize; layer >= 0; layer-- {
		queriesShape[layer] = len(currentLayer)
		queriesByLayer[layer] = append([]int(nil), currentLayer...)
		if len(raw.Queries[layer]) > 0 && !intSlicesEqual(raw.Queries[layer], currentLayer) {
			panic(fmt.Sprintf("query mismatch at layer %d", layer))
		}
		if layer == 0 {
			break
		}
		nextLayer := make([]int, 0, len(currentLayer))
		seen := make(map[int]struct{}, len(currentLayer))
		for _, query := range currentLayer {
			parent := query / 2
			if _, ok := seen[parent]; ok {
				continue
			}
			seen[parent] = struct{}{}
			nextLayer = append(nextLayer, parent)
		}
		currentLayer = nextLayer
	}

	queriesBranching := make([][]uint8, maxLogSize+1)
	for layer := 0; layer < maxLogSize; layer++ {
		parents := queriesByLayer[layer]
		children := queriesByLayer[layer+1]
		childSet := make(map[int]struct{}, len(children))
		for _, child := range children {
			childSet[child] = struct{}{}
		}
		for _, parent := range parents {
			left := parent * 2
			right := left + 1
			var code uint8
			if _, ok := childSet[left]; ok {
				code |= 1
			}
			if _, ok := childSet[right]; ok {
				code |= 2
			}
			queriesBranching[layer] = append(queriesBranching[layer], code)
		}
	}

	nColumnsPerLogSize := make([]int, maxLogSize+1)
	for _, logSize := range raw.ColumnLogSizes {
		if logSize <= 0 {
			panic("column log size must be positive")
		}
		index := int(logSize)
		if index >= len(nColumnsPerLogSize) {
			panic("column log size exceeds max log size")
		}
		nColumnsPerLogSize[index]++
	}

	return merkleTestVector{
		Root:               root,
		ColumnLogSizes:     columnLogSizes,
		BaseLayerQueries:   baseLayerQueries,
		Values:             values,
		HashWitness:        hashWitness,
		NColumnsPerLogSize: nColumnsPerLogSize,
		QueriesShape:       queriesShape,
		QueriesBranching:   queriesBranching,
		MaxLogSize:         uint8(maxLogSize),
	}
}
