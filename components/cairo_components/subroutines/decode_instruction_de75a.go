package subroutines

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

type DecodeInstructionDE75AResult struct {
	Offset0MinusBase m31.QM31
	VerifySum        m31.QM31
	Sum              m31.QM31
}

func DecodeInstructionDE75AEvaluate(
	qm31 *m31.QM31Chip,
	inputPC m31.QM31,
	offset0 m31.QM31,
	dstBaseFP m31.QM31,
	apUpdateAdd1 m31.QM31,
	verifyInstructionElements m31.InteractionElements,
	sum m31.QM31,
	domainVanishInv m31.QM31,
	randomCoeff m31.QM31,
) DecodeInstructionDE75AResult {
	one := qm31.One()

	// dst_base_fp is a bit.
	constraint := qm31.Mul(dstBaseFP, qm31.Sub(one, dstBaseFP))
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	// ap_update_add_1 is a bit.
	constraint = qm31.Mul(apUpdateAdd1, qm31.Sub(one, apUpdateAdd1))
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	alpha := qm31.Add(qm31.Mul(dstBaseFP, qm31Const(8)), qm31Const(16))
	alpha = qm31.Add(alpha, qm31Const(32))

	beta := qm31.Add(qm31Const(8), qm31.Mul(apUpdateAdd1, qm31Const(32)))

	values := []m31.QM31{
		inputPC,
		offset0,
		qm31Const(32767),
		qm31Const(32769),
		alpha,
		beta,
		qm31Const(0),
	}

	verifySum, err := qm31.Combine(verifyInstructionElements, values)
	if err != nil {
		panic(err)
	}

	return DecodeInstructionDE75AResult{
		Offset0MinusBase: qm31.Sub(offset0, qm31Const(32768)),
		VerifySum:        verifySum,
		Sum:              sum,
	}
}
