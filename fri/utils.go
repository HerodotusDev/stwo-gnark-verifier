package fri

import (
	"math/big"

	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
)

// EncodeFriAnswers encodes the FRI answers into a slice of slices of frontend.Variables according to the QM31 encoding.
func EncodeFriAnswers(qm31Chip *m31.QM31Chip, friAnswers [][]m31.QM31) [][]frontend.Variable {
	encodedFriAnswers := make([][]frontend.Variable, len(friAnswers))
	for i, friAnswer := range friAnswers {
		encodedFriAnswers[i] = make([]frontend.Variable, len(friAnswer))
		for j, m31Answer := range friAnswer {
			encodedFriAnswers[i][j] = qm31Chip.EncodeNative(m31Answer)
		}
	}
	return encodedFriAnswers
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

// friWitnessHint returns the witness values for the given inputs.
// It always returns a witness value (guessing if it is needed based on the provided flags)
func friWitnessHint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	// extract the inputs
	isLeftQueried := inputs[0].Uint64()
	isRightQueried := inputs[1].Uint64()
	// witness index points to the next unused hash witness entry (as a list of QM31s)
	witnessIndex := int(inputs[2].Uint64())
	// witness is passed as a flat []*big.Int (so a singe witness entry is 4 consecutive big.Ints)
	witness := inputs[3:]

	// initialize the result with a dummy witness value by default
	results[0] = big.NewInt(0)
	results[1] = big.NewInt(0)
	results[2] = big.NewInt(0)
	results[3] = big.NewInt(0)

	// fill the result with the needed witness value
	if isLeftQueried == 1 {
		if isRightQueried == 1 {
			// no witness needed, keep dummy witness
		} else {
			// right witness needed
			results[0] = witness[4*witnessIndex+0]
			results[1] = witness[4*witnessIndex+1]
			results[2] = witness[4*witnessIndex+2]
			results[3] = witness[4*witnessIndex+3]
			witnessIndex++
		}
	} else {
		// left witness needed
		results[0] = witness[4*witnessIndex+0]
		results[1] = witness[4*witnessIndex+1]
		results[2] = witness[4*witnessIndex+2]
		results[3] = witness[4*witnessIndex+3]
		witnessIndex++
	}

	// set the witness index to the next unused witness entry
	results[4] = big.NewInt(int64(witnessIndex))

	return nil
}
