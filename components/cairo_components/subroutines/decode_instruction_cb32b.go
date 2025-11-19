package subroutines

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

type DecodeInstructionCB32BResult struct {
	Offset0MinusBase m31.QM31
	Offset1MinusBase m31.QM31
	Offset2MinusBase m31.QM31
	VerifySum        m31.QM31
	Sum              m31.QM31
}

func DecodeInstructionCB32BEvaluate(
	qm31 *m31.QM31Chip,
	inputPC m31.QM31,
	offset0 m31.QM31,
	offset1 m31.QM31,
	offset2 m31.QM31,
	dstBaseFP m31.QM31,
	op0BaseFP m31.QM31,
	apUpdateAdd1 m31.QM31,
	verifyInstructionElements m31.InteractionElements,
	sum m31.QM31,
	domainVanishInv m31.QM31,
	randomCoeff m31.QM31,
) DecodeInstructionCB32BResult {
	one := qm31.One()

	// dst_base_fp is a bit.
	constraint := qm31.Mul(dstBaseFP, qm31.Sub(one, dstBaseFP))
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	// op0_base_fp is a bit.
	constraint = qm31.Mul(op0BaseFP, qm31.Sub(one, op0BaseFP))
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	// ap_update_add_1 is a bit.
	constraint = qm31.Mul(apUpdateAdd1, qm31.Sub(one, apUpdateAdd1))
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	alpha := qm31.Add(
		qm31.Mul(dstBaseFP, qm31Const(8)),
		qm31.Mul(op0BaseFP, qm31Const(16)),
	)

	beta := qm31.Add(qm31.Mul(apUpdateAdd1, qm31Const(32)), qm31Const(256))

	values := []m31.QM31{
		inputPC,
		offset0,
		offset1,
		offset2,
		alpha,
		beta,
		qm31Const(0),
	}

	var err error
	verifySum, err := qm31.Combine(verifyInstructionElements, values)
	if err != nil {
		panic(err)
	}

	return DecodeInstructionCB32BResult{
		Offset0MinusBase: qm31.Sub(offset0, qm31Const(32768)),
		Offset1MinusBase: qm31.Sub(offset1, qm31Const(32768)),
		Offset2MinusBase: qm31.Sub(offset2, qm31Const(32768)),
		VerifySum:        verifySum,
		Sum:              sum,
	}
}
