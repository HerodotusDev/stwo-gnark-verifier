package fri

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/blake2s"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

const NQUERIES = 10

type MerkleDecommitment struct {
	HashWitness [][32]uints.U8
}

type MerkleVerifier struct {
	api         frontend.API
	m31Chip     *m31.M31Chip
	uapi        *uints.BinaryField[uints.U32]
	blake2sChip *blake2s.Blake2sChip

	root               [32]uints.U8
	columnLogSizes     []uint8
	nColumnsPerLogSize map[uint8]int
}

func NewMerkleVerifier(api frontend.API, root [32]uints.U8, columnLogSizes []uint8) *MerkleVerifier {
	m31Chip := m31.NewM31Chip(api)
	uapi, err := uints.New[uints.U32](api)
	blake2sChip := blake2s.NewBlake2sChip(api)
	if err != nil {
		panic(err)
	}

	nColumnsPerLogSize := make(map[uint8]int)
	for _, logSize := range columnLogSizes {
		nColumnsPerLogSize[logSize]++
	}

	return &MerkleVerifier{
		api:                api,
		m31Chip:            m31Chip,
		uapi:               uapi,
		blake2sChip:        blake2sChip,
		root:               root,
		columnLogSizes:     columnLogSizes,
		nColumnsPerLogSize: nColumnsPerLogSize,
	}
}

func (v *MerkleVerifier) Verify(queries []uints.U32, queriedValues []m31.M31, decommitment *MerkleDecommitment) {
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

	// find the maximum log size
	maxLogSize := uint8(0)
	for _, logSize := range v.columnLogSizes {
		if logSize > maxLogSize {
			maxLogSize = logSize
		}
	}

	// compute the layer queries, initialized at 2 * initial_queries so that nodeIndex yields the correct index
	prevLayerQueries := [NQUERIES]uints.U32{}
	for i := 0; i < NQUERIES; i++ {
		prevLayerQueries[i] = v.uapi.Add(queries[i], queries[i])
	}

	// buffer for the previous layer hashes
	prevLayerHashes := [NQUERIES][32]uints.U8{}

	// decommit layer by layer, doing all queries at once
	for layerLog := maxLogSize; ; layerLog-- {
		nColumnsInLayer := v.nColumnsPerLogSize[layerLog]
		currentLayerQueries := [NQUERIES]uints.U32{}
		currentLayerHashes := [NQUERIES][32]uints.U8{}

		// go through all query positions in the previous layer
		for queryIndex, prevLayerQuery := range prevLayerQueries {
			// derive the current query position from the previous one (divide by 2)
			nodeIndex := v.uapi.Rshift(prevLayerQuery, 1)

			var columnValues []m31.M31
			// note that the following if-else branches can be evaluated at compile time
			// since the number of columns in each layer is a constant to the circuit
			if nColumnsInLayer > 0 {
				// pop the front of the queried values if any
				columnValues = remainingValues[:nColumnsInLayer]
				remainingValues = remainingValues[nColumnsInLayer:]
			}
			if layerLog == maxLogSize { // for the largest layer, there are no children to hash, just hash the columnvalues
				// hash the column values
				nodeHash := v.blake2sChip.HashNode(nil, nil, columnValues)

				// update the current layer hashes and queries
				currentLayerHashes[queryIndex] = nodeHash
				currentLayerQueries[queryIndex] = nodeIndex
			} else { // for the other layers, hash the children and the column values
				// fetch the previous layer computed hash
				childHash := prevLayerHashes[queryIndex]

				// fetch the sibling of childHash
				siblingHash := nextHashWitness()

				// reorder sibling and child hashes (if prevLayerQuery = 2*nodeIndex, previous layer queried the left child)
				rightChildIndex := v.uapi.Add(v.uapi.Add(nodeIndex, nodeIndex), uints.NewU32(1))
				isLeftQueried := v.api.Sub(v.uapi.ToValue(rightChildIndex), v.uapi.ToValue(prevLayerQuery))
				leftHash := v.selectHash(isLeftQueried, childHash, siblingHash)
				rightHash := v.selectHash(isLeftQueried, siblingHash, childHash)

				// hash the children and the column values
				nodeHash := v.blake2sChip.HashNode(leftHash[:], rightHash[:], columnValues)

				// update the current layer hashes and queries
				currentLayerHashes[queryIndex] = nodeHash
				currentLayerQueries[queryIndex] = nodeIndex
			}
		}
		// update the previous layer hashes and queries
		prevLayerHashes = currentLayerHashes
		prevLayerQueries = currentLayerQueries

		if layerLog == 0 {
			break
		}
	}

	// assert root match for all queries
	for queryIndex := range prevLayerHashes {
		for i := 0; i < 32; i++ {
			v.uapi.AssertIsEqual(prevLayerHashes[queryIndex][i], v.root[i])
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

func (v *MerkleVerifier) selectHash(selector frontend.Variable, whenTrue, whenFalse [32]uints.U8) [32]uints.U8 {
	var out [32]uints.U8
	for i := 0; i < len(out); i++ {
		out[i] = v.uapi.Select(selector, whenTrue[i], whenFalse[i])
	}
	return out
}
