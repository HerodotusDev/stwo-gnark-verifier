package subroutines

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

type RangeCheckLastLimbBitsInMsLimb6Result struct {
	Sum            m31.QM31
	RangeCheck6Sum m31.QM31
}

func RangeCheckLastLimbBitsInMsLimb6Evaluate(
	qm31 *m31.QM31Chip,
	input m31.QM31,
	rangeCheck6Elements m31.InteractionElements,
	sum m31.QM31,
	_ m31.QM31,
	_ m31.QM31,
) RangeCheckLastLimbBitsInMsLimb6Result {
	RangeCheck6Sum, err := qm31.Combine(rangeCheck6Elements, []m31.QM31{input})
	if err != nil {
		panic(err)
	}

	return RangeCheckLastLimbBitsInMsLimb6Result{
		Sum:            sum,
		RangeCheck6Sum: RangeCheck6Sum,
	}
}
