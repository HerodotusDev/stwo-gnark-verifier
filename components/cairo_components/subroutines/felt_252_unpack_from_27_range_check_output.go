package subroutines

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

type Felt252UnpackFrom27RangeCheckOutputResult struct {
	Sum            m31.QM31
	RangeCheckSums [14]m31.QM31
	Outputs        [10]m31.QM31
}

func Felt252UnpackFrom27RangeCheckOutputEvaluate(
	qm31 *m31.QM31Chip,
	inputs [10]m31.QM31,
	lowLimbs [9]m31.QM31,
	highLimbs [9]m31.QM31,
	rangeCheckElements m31.InteractionElements,
	sum m31.QM31,
	domainVanishInv m31.QM31,
	randomCoeff m31.QM31,
) Felt252UnpackFrom27RangeCheckOutputResult {
	constFactor := qm31Const(8192)
	scale := qm31Const(512)

	var computed [10]m31.QM31
	for i := 0; i < 9; i++ {
		value := qm31.Sub(inputs[i], lowLimbs[i])
		value = qm31.Sub(value, qm31.Mul(highLimbs[i], scale))
		computed[i] = qm31.Mul(value, constFactor)
	}
	computed[9] = inputs[9]

	values := make([]m31.QM31, 0, 28)
	for i := 0; i < 9; i++ {
		values = append(values, lowLimbs[i], highLimbs[i], computed[i])
	}
	values = append(values, computed[9])

	rcRes := RangeCheckMemValueN28Evaluate(
		qm31,
		values,
		rangeCheckElements,
		sum,
		domainVanishInv,
		randomCoeff,
	)
	sum = rcRes.Sum

	return Felt252UnpackFrom27RangeCheckOutputResult{
		Sum:            sum,
		RangeCheckSums: rcRes.RangeSums14,
		Outputs:        computed,
	}
}
