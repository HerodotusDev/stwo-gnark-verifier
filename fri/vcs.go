package fri

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/blake2s"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/HerodotusDev/stwo-gnark-verifier/variables"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

const NQUERIES = 10

type MerkleVerifier struct {
	api         frontend.API
	m31Chip     *m31.M31Chip
	uapi        *uints.BinaryField[uints.U32]
	blake2sChip *blake2s.Blake2sChip

	root               [32]uints.U8
	ColumnLogSizes     []frontend.Variable
	nColumnsPerLogSize []int
}

func NewMerkleVerifier(api frontend.API, uapi *uints.BinaryField[uints.U32], root [32]uints.U8, columnLogSizes []frontend.Variable, nColumnsPerLogSize []int) *MerkleVerifier {
	m31Chip := m31.NewM31Chip(api)
	blake2sChip := blake2s.NewBlake2sChip(api)

	return &MerkleVerifier{
		api:                api,
		m31Chip:            m31Chip,
		uapi:               uapi,
		blake2sChip:        blake2sChip,
		root:               root,
		ColumnLogSizes:     columnLogSizes,
		nColumnsPerLogSize: nColumnsPerLogSize,
	}
}

// Verify verifies the Merkle decommitment for the given queries and queried values
//   - queries[l] contains the queries for the layer of log size l, len(queries) should be the number of layers (from root to leaves).
//     For all l, queries[l] is sorted ascending.
func (v *MerkleVerifier) Verify(queries [][]int, queriedValues []m31.M31, decommitment variables.MerkleDecommitment) {
	remainingValues := queriedValues
	hashWitness := decommitment.HashWitness
	hashWitnessIndex := 0

	// helper function replicating the rust api for iterator next() method
	nextHashWitness := func() [32]uints.U8 {
		if hashWitnessIndex >= len(hashWitness) {
			panic("merkle hash witness exhausted")
		}
		hash := hashWitness[hashWitnessIndex]
		hashWitnessIndex++
		return hash
	}

	// find the log size of the largest layer
	maxLogSize := uint8(0)
	for _, logSize := range v.ColumnLogSizes {
		if logSize > maxLogSize {
			maxLogSize = logSize
		}
	}

	// extend the queries so that for layers with no columns node hashes are still computed
	extendedQueries := extendQueries(queries, maxLogSize)

	// storage for the hashes per layer, keyed by log size
	layerHashes := make(map[uint8][][32]uints.U8)

	// decommit layer by layer, doing all queries at once
	for layerLog := maxLogSize; ; layerLog-- {
		nColumnsInLayer := v.nColumnsPerLogSize[layerLog-1]
		j := 0 // pointer to the previous layer query

		// go through all query positions of the current layer
		for _, query := range extendedQueries[layerLog] {
			var columnValues []m31.M31
			// note that the following if-else branches can be evaluated at compile time
			// since the number of columns and the queries in each layer are constants to the circuit
			if nColumnsInLayer > 0 {
				// pop the front of the queried values if any
				columnValues = remainingValues[:nColumnsInLayer]
				remainingValues = remainingValues[nColumnsInLayer:]
			}

			if layerLog == maxLogSize {
				// for the largest layer, there are no children to hash, just hash the column values
				layerHashes[layerLog] = append(layerHashes[layerLog], v.blake2sChip.HashNode(nil, nil, columnValues))
			} else {
				// derive the children queries candidates
				queryMulTwo := 2 * query
				leftCandidate := queryMulTwo
				rightCandidate := queryMulTwo + 1

				var leftHash [32]uints.U8
				var rightHash [32]uints.U8

				if j < len(extendedQueries[layerLog+1]) && leftCandidate == extendedQueries[layerLog+1][j] {
					// if the left candidate was queried get the left hash from the previous layer
					leftHash = layerHashes[layerLog+1][j]
					if j+1 < len(extendedQueries[layerLog+1]) && extendedQueries[layerLog+1][j+1] == rightCandidate {
						// if the right candidate was also queried get the right hash from the previous layer
						rightHash = layerHashes[layerLog+1][j+1]
						j += 2
					} else {
						// if the right candidate was not queried, get the right hash from the witness
						rightHash = nextHashWitness()
						j++
					}
				} else if j < len(extendedQueries[layerLog+1]) && rightCandidate == extendedQueries[layerLog+1][j] {
					// if the right candidate was queried get the right hash from the previous layer and the left hash from the witness
					leftHash = nextHashWitness()
					rightHash = layerHashes[layerLog+1][j]
					j++
				} else {
					leftHash = nextHashWitness()
					rightHash = nextHashWitness()
				}

				// update the current layer hashes
				layerHashes[layerLog] = append(layerHashes[layerLog], v.blake2sChip.HashNode(leftHash[:], rightHash[:], columnValues))
			}
		}

		// assert no unused queries
		if layerLog != maxLogSize {
			v.api.AssertIsEqual(j, len(extendedQueries[layerLog+1]))
		}

		if layerLog == 0 {
			break
		}
	}

	// assert root match for all queries
	for queryIndex := range layerHashes[0] {
		for i := 0; i < 32; i++ {
			v.uapi.AssertIsEqual(layerHashes[0][queryIndex][i], v.root[i])
		}
	}

	// assert no unused hash witness entries
	if hashWitnessIndex != len(hashWitness) {
		panic("unused hash witness entries in Merkle decommitment")
	}
	// assert no unused queried values
	if len(remainingValues) != 0 {
		panic("unused queried values in Merkle decommitment")
	}

}

// TODO: this is unchecked hinting, the extension should be made before the query checking (and add a flag for extended queries)
func extendQueries(queries [][]int, maxLogSize uint8) [][]int {
	extendedQueries := make([][]int, maxLogSize+1)
	for layerLog := maxLogSize; ; layerLog-- {
		if len(queries[layerLog]) > 0 {
			extendedQueries[layerLog] = queries[layerLog]
			continue
		} else {
			childQueries := extendedQueries[layerLog+1] // layerLog+1 <= maxLogSize since len(queries[maxLogSize]) > 0
			derivedQueries := make([]int, 0, len(childQueries))
			for _, childQuery := range childQueries {
				parentQuery := childQuery / 2
				if len(derivedQueries) == 0 || derivedQueries[len(derivedQueries)-1] != parentQuery {
					derivedQueries = append(derivedQueries, parentQuery)
				}
			}
			extendedQueries[layerLog] = derivedQueries
		}

		if layerLog == 0 {
			break
		}
	}
	return extendedQueries
}
