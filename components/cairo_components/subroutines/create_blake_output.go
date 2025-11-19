package subroutines

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

type TripleXorPair struct {
	Limb0 m31.QM31
	Limb1 m31.QM31
}

type CreateBlakeOutputResult struct {
	Sum        m31.QM31
	LookupSums [8]m31.QM31
}

func CreateBlakeOutputEvaluate(
	qm31 *m31.QM31Chip,
	input []m31.QM31,
	outputPairs [8]TripleXorPair,
	elements m31.InteractionElements,
	sum m31.QM31,
	_ m31.QM31,
	_ m31.QM31,
) CreateBlakeOutputResult {
	if len(input) != 48 {
		panic("CreateBlakeOutputEvaluate expects 48 input limbs")
	}

	var lookupSums [8]m31.QM31
	for i := 0; i < 8; i++ {
		values := []m31.QM31{
			input[16+2*i],
			input[16+2*i+1],
			input[32+2*i],
			input[32+2*i+1],
			input[2*i],
			input[2*i+1],
			outputPairs[i].Limb0,
			outputPairs[i].Limb1,
		}

		sumVal, err := qm31.Combine(elements, values)
		if err != nil {
			panic(err)
		}
		lookupSums[i] = sumVal
	}

	return CreateBlakeOutputResult{
		Sum:        sum,
		LookupSums: lookupSums,
	}
}
