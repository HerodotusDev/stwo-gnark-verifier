package fri

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/blake2s"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/HerodotusDev/stwo-gnark-verifier/utils"
	"github.com/HerodotusDev/stwo-gnark-verifier/variables"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
	"github.com/consensys/gnark/std/math/uints"
)

// MerkleVerifier is a circuit gadget for verifying a Merkle decommitment
type MerkleVerifier struct {
	api         frontend.API
	uapi        *uints.BinaryField[uints.U32]
	bapi        *uints.Bytes
	m31Chip     *m31.M31Chip
	blake2sChip *blake2s.Blake2sChip

	root               [32]uints.U8
	ColumnLogSizes     []frontend.Variable
	nColumnsPerLogSize []int
	maxLogSize         int
}

// NewMerkleVerifier initializes a new MerkleVerifier
func NewMerkleVerifier(api frontend.API, uapi *uints.BinaryField[uints.U32], root [32]uints.U8, columnLogSizes []frontend.Variable, nColumnsPerLogSize []int) *MerkleVerifier {
	m31Chip := m31.NewM31Chip(api)
	blake2sChip := blake2s.NewBlake2sChip(api)
	bapi, err := uints.NewBytes(api)
	if err != nil {
		panic(err)
	}

	maxLogSize := 0
	for i, nColumns := range nColumnsPerLogSize {
		if nColumns > 0 {
			maxLogSize = i
		}
	}

	return &MerkleVerifier{
		api:                api,
		uapi:               uapi,
		bapi:               bapi,
		m31Chip:            m31Chip,
		blake2sChip:        blake2sChip,
		root:               root,
		ColumnLogSizes:     columnLogSizes,
		nColumnsPerLogSize: nColumnsPerLogSize,
		maxLogSize:         maxLogSize,
	}
}

// Verify verifies the Merkle decommitment for the given queries and queried values
//   - queries[l] contains the queries for the layer of log size l, len(queries) should be the number of layers (from root to leaves).
//     For all l, queries[l] is sorted ascending with a dummy query at the end. IMPORTANT: queries[l] is never empty and should be generated from GenerateQueries.
//   - queriesShape[l] = len(queries[l]) - 1 (-1 for the dummy query)
//   - queriesBranching[l][i] encodes which children are present for queries[l][i]:
//     bit 0 for left, bit 1 for right
func (v *MerkleVerifier) Verify(queries []logderivlookup.Table, queriedValues []m31.M31, decommitment variables.MerkleDecommitment, queriesShape []int, queriesBranching [][]uint8) {
	remainingValues := queriedValues
	witnessIndex := 0
	zeroHash := [32]uints.U8{}
	for i := range zeroHash {
		zeroHash[i] = uints.NewU8(0)
	}

	// storage for the hashes per layer, keyed by log size
	layerHashes := make([]logderivlookup.Table, v.maxLogSize+1)
	// decommit layer by layer, doing all queries at once
	for layerLog := v.maxLogSize; ; layerLog-- {
		// initialize the layer hashes
		layerHashes[layerLog] = logderivlookup.New(v.api)
		// get the number of columns in the layer
		nColumnsInLayer := v.nColumnsPerLogSize[layerLog]
		// j is a pointer to the previous layer query.
		j := 0

		// go through all query positions of the current layer
		for queryIndex := 0; queryIndex < queriesShape[layerLog]; queryIndex++ {
			query := queries[layerLog].Lookup(queryIndex)[0]
			_ = query // keep lookup constraints even though branching is static
			// pop the front of the queried values if any
			var columnValues []m31.M31
			if nColumnsInLayer > 0 {
				columnValues = remainingValues[:nColumnsInLayer]
				remainingValues = remainingValues[nColumnsInLayer:]
			}

			// for the largest layer, there are no children to hash, just hash the column values
			if layerLog == v.maxLogSize {
				hash := v.blake2sChip.HashNode(nil, nil, columnValues)
				lo, hi := utils.SplitHash(v.api, hash)
				layerHashes[layerLog].Insert(lo)
				layerHashes[layerLog].Insert(hi)
			} else {
				if layerLog >= len(queriesBranching) {
					panic("queries branching missing layer data")
				}
				if queryIndex >= len(queriesBranching[layerLog]) {
					panic("queries branching length mismatch")
				}
				branchCode := queriesBranching[layerLog][queryIndex]
				leftPresent := branchCode&1 == 1
				rightPresent := branchCode&2 == 2

				var leftHash [32]uints.U8
				var rightHash [32]uints.U8

				// rebuild the children hashes candidates from the previous layer
				twoJ := 2 * j
				h0Lo := layerHashes[layerLog+1].Lookup(frontend.Variable(twoJ))[0]
				h0Hi := layerHashes[layerLog+1].Lookup(frontend.Variable(twoJ + 1))[0]
				h1Lo := layerHashes[layerLog+1].Lookup(frontend.Variable(twoJ + 2))[0]
				h1Hi := layerHashes[layerLog+1].Lookup(frontend.Variable(twoJ + 3))[0]
				h0 := utils.RebuildHash(v.api, h0Lo, h0Hi)
				h1 := utils.RebuildHash(v.api, h1Lo, h1Hi)

				var w0 [32]uints.U8
				var w1 [32]uints.U8
				if leftPresent {
					leftHash = h0
					if rightPresent {
						w0 = zeroHash
						w1 = zeroHash
						rightHash = h1
					} else {
						w0 = zeroHash
						w1 = decommitment.HashWitness[witnessIndex]
						witnessIndex++
						rightHash = w1
					}
				} else if rightPresent {
					w0 = decommitment.HashWitness[witnessIndex]
					witnessIndex++
					w1 = zeroHash
					leftHash = w0
					rightHash = h0
				} else {
					w0 = decommitment.HashWitness[witnessIndex]
					w1 = decommitment.HashWitness[witnessIndex+1]
					witnessIndex += 2
					leftHash = w0
					rightHash = w1
				}

				if leftPresent {
					if rightPresent {
						j += 2
					} else {
						j++
					}
				} else if rightPresent {
					j++
				}

				// update the current layer hashes
				hash := v.blake2sChip.HashNode(leftHash[:], rightHash[:], columnValues)
				lo, hi := utils.SplitHash(v.api, hash)
				layerHashes[layerLog].Insert(lo)
				layerHashes[layerLog].Insert(hi)
			}
		}
		// append a dummy hash to the end of the layer, will never be used for hashing
		layerHashes[layerLog].Insert(frontend.Variable(0))
		layerHashes[layerLog].Insert(frontend.Variable(0))
		layerHashes[layerLog].Insert(frontend.Variable(0))
		layerHashes[layerLog].Insert(frontend.Variable(0))

		if layerLog == 0 {
			break
		}
	}

	// assert root match for all queries
	rootLo := layerHashes[0].Lookup(0)[0]
	rootHi := layerHashes[0].Lookup(1)[0]
	computedRoot := utils.RebuildHash(v.api, rootLo, rootHi)
	for i := 0; i < 32; i++ {
		v.uapi.AssertIsEqual(computedRoot[i], v.root[i])
	}

}
