package subroutines

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

type DecodeInstruction4B8CFResult struct {
	Offset0MinusBase m31.QM31
	Offset1MinusBase m31.QM31
	Offset2MinusBase m31.QM31
	Op1BaseAP        m31.QM31
	VerifySum        m31.QM31
	Sum              m31.QM31
}

func DecodeInstruction4B8CFEvaluate(
	qm31 *m31.QM31Chip,
	inputPC m31.QM31,
	offset0 m31.QM31,
	offset1 m31.QM31,
	offset2 m31.QM31,
	dstBaseFP m31.QM31,
	op0BaseFP m31.QM31,
	op1Imm m31.QM31,
	op1BaseFP m31.QM31,
	apUpdateAdd1 m31.QM31,
	verifyInstructionElements m31.InteractionElements,
	sum m31.QM31,
	domainVanishInv m31.QM31,
	randomCoeff m31.QM31,
) DecodeInstruction4B8CFResult {
	one := qm31.One()

	// dst_base_fp is a bit.
	constraint := qm31.Mul(dstBaseFP, qm31.Sub(one, dstBaseFP))
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	// op0_base_fp is a bit.
	constraint = qm31.Mul(op0BaseFP, qm31.Sub(one, op0BaseFP))
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	// op1_imm is a bit.
	constraint = qm31.Mul(op1Imm, qm31.Sub(one, op1Imm))
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	// op1_base_fp is a bit.
	constraint = qm31.Mul(op1BaseFP, qm31.Sub(one, op1BaseFP))
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	op1BaseAP := qm31.Sub(qm31.Sub(one, op1Imm), op1BaseFP)

	// op1_base_ap is a bit.
	constraint = qm31.Mul(op1BaseAP, qm31.Sub(one, op1BaseAP))
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	// ap_update_add_1 is a bit.
	constraint = qm31.Mul(apUpdateAdd1, qm31.Sub(one, apUpdateAdd1))
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	alpha := qm31Const(8)
	alpha = qm31.Add(alpha, qm31.Mul(op0BaseFP, qm31Const(16)))
	alpha = qm31.Add(alpha, qm31.Mul(op1Imm, qm31Const(32)))
	alpha = qm31.Add(alpha, qm31.Mul(op1BaseFP, qm31Const(64)))
	alpha = qm31.Add(alpha, qm31.Mul(op1BaseAP, qm31Const(128)))

	beta := qm31.Add(qm31Const(256), qm31.Mul(apUpdateAdd1, qm31Const(32)))
	beta = qm31.Add(beta, qm31Const(1))

	values := []m31.QM31{
		inputPC,
		offset0,
		offset1,
		offset2,
		alpha,
		beta,
		qm31Const(0),
	}

	verifySum, err := qm31.Combine(verifyInstructionElements, values)
	if err != nil {
		panic(err)
	}

	return DecodeInstruction4B8CFResult{
		Offset0MinusBase: qm31.Sub(offset0, qm31Const(32768)),
		Offset1MinusBase: qm31.Sub(offset1, qm31Const(32768)),
		Offset2MinusBase: qm31.Sub(offset2, qm31Const(32768)),
		Op1BaseAP:        op1BaseAP,
		VerifySum:        verifySum,
		Sum:              sum,
	}
}
