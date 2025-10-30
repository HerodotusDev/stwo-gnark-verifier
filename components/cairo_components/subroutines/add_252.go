package subroutines

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

type Add252Result struct {
	Sum            m31.QM31
	RangeCheckSums [14]m31.QM31
}

func Add252Evaluate(
	qm31 *m31.QM31Chip,
	aLimbs []m31.QM31,
	bLimbs []m31.QM31,
	resultLimbs []m31.QM31,
	subPBit m31.QM31,
	rangeCheckElements m31.InteractionElements,
	sum m31.QM31,
	domainVanishInv m31.QM31,
	randomCoeff m31.QM31,
) Add252Result {
	if len(aLimbs) != 28 || len(bLimbs) != 28 || len(resultLimbs) != 28 {
		panic("Add252Evaluate expects 28 limbs for each operand")
	}

	rcRes := RangeCheckMemValueN28Evaluate(
		qm31,
		resultLimbs,
		rangeCheckElements,
		sum,
		domainVanishInv,
		randomCoeff,
	)
	sum = rcRes.Sum

	sum = VerifyAdd252Evaluate(
		qm31,
		aLimbs,
		bLimbs,
		resultLimbs,
		subPBit,
		sum,
		domainVanishInv,
		randomCoeff,
	)

	return Add252Result{
		Sum:            sum,
		RangeCheckSums: rcRes.RangeSums14,
	}
}
