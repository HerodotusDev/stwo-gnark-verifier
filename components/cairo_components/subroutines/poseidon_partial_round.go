package subroutines

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

type PoseidonPartialRoundResult struct {
	Sum              m31.QM31
	CubeLookupSum    m31.QM31
	Range4444Sums    [2]m31.QM31
	Range44Sum       m31.QM31
	RangeFeltSum     m31.QM31
	Z13Outputs       [10]m31.QM31
	Z2Outputs        [10]m31.QM31
	CombinationRange LinearCombinationRangeResult
}

func PoseidonPartialRoundEvaluate(
	qm31 *m31.QM31Chip,
	input [50]m31.QM31,
	cubeOutputs [10]m31.QM31,
	combinationFirst [10]m31.QM31,
	combinationSecond [10]m31.QM31,
	pCoefFirst m31.QM31,
	pCoefSecond m31.QM31,
	cubeElements m31.InteractionElements,
	range4444Elements m31.InteractionElements,
	range44Elements m31.InteractionElements,
	rangeFeltElements m31.InteractionElements,
	sum m31.QM31,
	domainVanishInv m31.QM31,
	randomCoeff m31.QM31,
) PoseidonPartialRoundResult {
	var z0Cube, z1, z13, z2, halfKey [10]m31.QM31

	copy(z0Cube[:], input[0:10])
	copy(z1[:], input[10:20])
	copy(z13[:], input[20:30])
	copy(z2[:], input[30:40])
	copy(halfKey[:], input[40:50])

	values := make([]m31.QM31, 0, 20)
	values = append(values, z2[:]...)
	values = append(values, cubeOutputs[:]...)

	cubeSum, err := qm31.Combine(cubeElements, values)
	if err != nil {
		panic(err)
	}

	var linearInput [60]m31.QM31
	copy(linearInput[0:10], z0Cube[:])
	copy(linearInput[10:20], z1[:])
	copy(linearInput[20:30], z13[:])
	copy(linearInput[30:40], z2[:])
	copy(linearInput[40:50], cubeOutputs[:])
	copy(linearInput[50:60], halfKey[:])

	lcRes := LinearCombinationN6Coefs42_3_1M11Evaluate(
		qm31,
		linearInput,
		combinationFirst,
		pCoefFirst,
		range4444Elements,
		range44Elements,
		sum,
		domainVanishInv,
		randomCoeff,
	)
	sum = lcRes.Sum

	rangeFelt, err := qm31.Combine(rangeFeltElements, combinationFirst[:])
	if err != nil {
		panic(err)
	}

	sum = LinearCombinationN1Coefs2Evaluate(
		qm31,
		combinationFirst,
		combinationSecond,
		pCoefSecond,
		sum,
		domainVanishInv,
		randomCoeff,
	)

	return PoseidonPartialRoundResult{
		Sum:              sum,
		CubeLookupSum:    cubeSum,
		Range4444Sums:    [2]m31.QM31{lcRes.RangeSum0, lcRes.RangeSum1},
		Range44Sum:       lcRes.RangeSum2,
		RangeFeltSum:     rangeFelt,
		Z13Outputs:       z13,
		Z2Outputs:        z2,
		CombinationRange: lcRes,
	}
}
