package subroutines

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

type Div252Result struct {
	Sum             m31.QM31
	ResultRangeSums [14]m31.QM31
	CarryRangeSums  [28]m31.QM31
}

func Div252Evaluate(
	qm31 *m31.QM31Chip,
	cLimbs []m31.QM31,
	aLimbs []m31.QM31,
	resultLimbs []m31.QM31,
	k m31.QM31,
	carries []m31.QM31,
	rangeCheckResultElements m31.InteractionElements,
	rangeCheckCarryElements m31.InteractionElements,
	sum m31.QM31,
	domainVanishInv m31.QM31,
	randomCoeff m31.QM31,
) Div252Result {
	if len(cLimbs) != 28 || len(aLimbs) != 28 || len(resultLimbs) != 28 {
		panic("Div252Evaluate expects 28 limbs for operands")
	}
	if len(carries) != 27 {
		panic("Div252Evaluate expects 27 carry values")
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
		resultLimbs,
		cLimbs,
		k,
		carries,
		rangeCheckCarryElements,
		sum,
		domainVanishInv,
		randomCoeff,
	)
	sum = verifyRes.Sum

	return Div252Result{
		Sum:             sum,
		ResultRangeSums: rcRes.RangeSums14,
		CarryRangeSums:  verifyRes.RangeCheckSums,
	}
}
