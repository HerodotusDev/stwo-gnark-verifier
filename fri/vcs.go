package fri

import (
	"math/big"

	"github.com/HerodotusDev/stwo-gnark-verifier/blake2s"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/HerodotusDev/stwo-gnark-verifier/utils"
	"github.com/HerodotusDev/stwo-gnark-verifier/variables"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
	"github.com/consensys/gnark/std/math/cmp"
	"github.com/consensys/gnark/std/math/uints"
)

type MerkleVerifier struct {
	api         frontend.API
	uapi        *uints.BinaryField[uints.U32]
	bapi        *uints.Bytes
	m31Chip     *m31.M31Chip
	blake2sChip *blake2s.Blake2sChip

	root               [32]uints.U8
	ColumnLogSizes     []frontend.Variable
	nColumnsPerLogSize []int
}

func NewMerkleVerifier(api frontend.API, uapi *uints.BinaryField[uints.U32], root [32]uints.U8, columnLogSizes []frontend.Variable, nColumnsPerLogSize []int) *MerkleVerifier {
	m31Chip := m31.NewM31Chip(api)
	blake2sChip := blake2s.NewBlake2sChip(api)
	bapi, err := uints.NewBytes(api)
	if err != nil {
		panic(err)
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
	}
}

// Verify verifies the Merkle decommitment for the given queries and queried values
//   - queries[l] contains the queries for the layer of log size l, len(queries) should be the number of layers (from root to leaves).
//     For all l, queries[l] is sorted ascending with a dummy query at the end. IMPORTANT: queries[l] is never empty and should be generated from GenerateQueries.
//   - queriesShape[l] = len(queries[l]) - 1 (-1 for the dummy query)
func (v *MerkleVerifier) Verify(queries []logderivlookup.Table, queriedValues []m31.M31, decommitment variables.MerkleDecommitment, queriesShape []int) {
	remainingValues := queriedValues
	// there is no constraints on witnessIndex, it's just used as an external pointer for the hint function (frontend.Variable is
	// not needed but convenient for hint signature)
	witnessIndex := frontend.Variable(0)

	// find the log size of the largest layer
	maxLogSize := uint8(len(queries) - 1)

	// storage for the hashes per layer, keyed by log size
	layerHashes := make([]logderivlookup.Table, maxLogSize+1)

	// decommit layer by layer, doing all queries at once
	for layerLog := maxLogSize; ; layerLog-- {
		// initialize the layer hashes
		layerHashes[layerLog] = logderivlookup.New(v.api)
		// get the number of columns in the layer
		nColumnsInLayer := v.nColumnsPerLogSize[layerLog]
		// j is a pointer to the previous layer query.
		j := frontend.Variable(0)

		// go through all query positions of the current layer
		for queryIndex := 0; queryIndex < queriesShape[layerLog]; queryIndex++ {
			query := queries[layerLog].Lookup(queryIndex)[0]
			// pop the front of the queried values if any
			var columnValues []m31.M31
			if nColumnsInLayer > 0 {
				columnValues = remainingValues[:nColumnsInLayer]
				remainingValues = remainingValues[nColumnsInLayer:]
			}

			// for the largest layer, there are no children to hash, just hash the column values
			if layerLog == maxLogSize {
				hash := v.blake2sChip.HashNode(nil, nil, columnValues)
				lo, hi := utils.SplitHash(v.api, hash)
				layerHashes[layerLog].Insert(lo)
				layerHashes[layerLog].Insert(hi)
			} else {
				jPlusOne := v.api.Add(j, frontend.Variable(1))
				jPlusTwo := v.api.Add(j, frontend.Variable(2))
				twoJ := v.api.Mul(j, frontend.Variable(2))
				twoJPlusOne := v.api.Add(twoJ, frontend.Variable(1))
				twoJPlusTwo := v.api.Add(twoJ, frontend.Variable(2))
				twoJPlusThree := v.api.Add(twoJ, frontend.Variable(3))

				// derive the children queries candidates
				queryMulTwo := v.api.Mul(query, frontend.Variable(2))
				leftCandidate := queryMulTwo
				rightCandidate := v.api.Add(queryMulTwo, frontend.Variable(1))

				var leftHash [32]uints.U8
				var rightHash [32]uints.U8

				// rebuild the children hashes candidates from the previous layer
				h0Lo := layerHashes[layerLog+1].Lookup(twoJ)[0]
				h0Hi := layerHashes[layerLog+1].Lookup(twoJPlusOne)[0]
				h1Lo := layerHashes[layerLog+1].Lookup(twoJPlusTwo)[0]
				h1Hi := layerHashes[layerLog+1].Lookup(twoJPlusThree)[0]
				h0 := utils.RebuildHash(v.api, h0Lo, h0Hi)
				h1 := utils.RebuildHash(v.api, h1Lo, h1Hi)

				isLeftQueried := cmp.IsEqual(v.api, leftCandidate, queries[layerLog+1].Lookup(j)[0])
				isRightAlsoQueried := cmp.IsEqual(v.api, rightCandidate, queries[layerLog+1].Lookup(jPlusOne)[0])
				isJustRightQueried := cmp.IsEqual(v.api, rightCandidate, queries[layerLog+1].Lookup(j)[0])

				// aggregate the arguments to comply with the hint signature
				args := []frontend.Variable{isLeftQueried, isRightAlsoQueried, isJustRightQueried, witnessIndex}
				for _, hash := range decommitment.HashWitness {
					hashNative := [32]frontend.Variable{}
					for i := 0; i < 32; i++ {
						hashNative[i] = v.bapi.Value(hash[i])
					}
					args = append(args, hashNative[:]...)
				}
				// the soundness relies on the fact that it is too costly to forge a valid witness for a given query, so it doesn't need to be checked
				hintedWitness, err := v.api.Compiler().NewHint(WitnessHint, 2*32+1, args...)
				if err != nil {
					panic(err)
				}

				// extract the witness values from the hinted witness
				var w0 [32]uints.U8
				var w1 [32]uints.U8
				for i := 0; i < 32; i++ {
					w0[i] = v.bapi.ValueOf(hintedWitness[i])
				}
				for i := 0; i < 32; i++ {
					w1[i] = v.bapi.ValueOf(hintedWitness[32+i])
				}

				// update the witness index from the hinted witness
				witnessIndex = hintedWitness[2*32]

				leftHash = utils.SelectHash(v.api, isLeftQueried, h0, w0)
				intermediate1 := utils.SelectHash(v.api, isRightAlsoQueried, h1, w1)
				intermediate2 := utils.SelectHash(v.api, isJustRightQueried, h0, w1)
				rightHash = utils.SelectHash(v.api, isLeftQueried, intermediate1, intermediate2)

				// update the pointer to the previous layer query
				j = v.api.Select(
					isLeftQueried,
					v.api.Select(isRightAlsoQueried, jPlusTwo, jPlusOne),
					v.api.Select(isJustRightQueried, jPlusOne, j),
				)

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

// WitnessHint returns the witness values for the given inputs.
// It always returns 2 witness values in a predictable order (guessing which one will be needed based on the provided flags)
func WitnessHint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	// extract the inputs
	isLeftQueried := inputs[0].Uint64()
	isRightAlsoQueried := inputs[1].Uint64()
	isJustRightQueried := inputs[2].Uint64()
	// witness index points to the next unused hash witness entry (as a list of [32]uints.U8)
	witnessIndex := int(inputs[3].Uint64())
	// hashWitness is passed as a flat []*big.Int (so a singe witness entry is 32 consecutive big.Ints)
	hashWitness := inputs[4:]

	// initialize the results with dummy witness values by default
	for i := 0; i < 64; i++ {
		results[i] = big.NewInt(0)
	}
	// fill the results with the needed witness values
	if isLeftQueried == 1 {
		if isRightAlsoQueried == 1 {
			// no witness needed, keep dummy witness
		} else {
			// right witness needed
			for i := 0; i < 32; i++ {
				results[32+i] = hashWitness[32*witnessIndex+i]
			}
			witnessIndex++
		}
	} else {
		if isJustRightQueried == 1 {
			// left witness needed
			for i := 0; i < 32; i++ {
				results[i] = hashWitness[32*witnessIndex+i]
			}
			witnessIndex++
		} else {
			// both witnesses needed
			for i := 0; i < 32; i++ {
				results[i] = hashWitness[32*witnessIndex+i]
			}
			for i := 0; i < 32; i++ {
				results[32+i] = hashWitness[32*(witnessIndex+1)+i]
			}
			witnessIndex += 2
		}
	}

	// set the witness index to the next unused hash witness entry
	results[64] = big.NewInt(int64(witnessIndex))

	return nil
}
