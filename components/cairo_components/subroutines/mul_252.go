package subroutines

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

type Mul252Result struct {
	Sum             m31.QM31
	ResultRangeSums [14]m31.QM31
	CarryRangeSums  [28]m31.QM31
}

func Mul252Evaluate(
	qm31 *m31.QM31Chip,
	aLimbs []m31.QM31,
	bLimbs []m31.QM31,
	resultLimbs []m31.QM31,
	k m31.QM31,
	carries []m31.QM31,
	rangeCheckResultElements m31.InteractionElements,
	rangeCheckCarryElements m31.InteractionElements,
	sum m31.QM31,
	domainVanishInv m31.QM31,
	randomCoeff m31.QM31,
) Mul252Result {
	if len(aLimbs) != 28 || len(bLimbs) != 28 || len(resultLimbs) != 28 {
		panic("Mul252Evaluate expects 28 limbs for operands")
	}
	if len(carries) != 27 {
		panic("Mul252Evaluate expects 27 carry values")
	}

	rcRes := RangeCheckMemValueN28Evaluate(
		qm31,
		resultLimbs,
		rangeCheckResultElements,
		sum,
		domainVanishInv,
		randomCoeff,
	)
	sum = rcRes.Sum

	verifyRes := VerifyMul252Evaluate(
		qm31,
		aLimbs,
		bLimbs,
		resultLimbs,
		k,
		carries,
		rangeCheckCarryElements,
		sum,
		domainVanishInv,
		randomCoeff,
	)
	sum = verifyRes.Sum

	return Mul252Result{
		Sum:             sum,
		ResultRangeSums: rcRes.RangeSums14,
		CarryRangeSums:  verifyRes.RangeCheckSums,
	}
}
