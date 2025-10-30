package subroutines

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

type DecodeInstruction64420Result struct {
	Offset0MinusBase m31.QM31
	Offset1MinusBase m31.QM31
	Offset2MinusBase m31.QM31
	VerifySum        m31.QM31
	Sum              m31.QM31
}

func DecodeInstruction64420Evaluate(
	qm31 *m31.QM31Chip,
	inputPC m31.QM31,
	offset0 m31.QM31,
	offset1 m31.QM31,
	offset2 m31.QM31,
	dstBaseFP m31.QM31,
	op0BaseFP m31.QM31,
	op1BaseFP m31.QM31,
	op1BaseAP m31.QM31,
	apUpdateAdd1 m31.QM31,
	opcodeExtension m31.QM31,
	verifyInstructionElements m31.InteractionElements,
	sum m31.QM31,
	domainVanishInv m31.QM31,
	randomCoeff m31.QM31,
) DecodeInstruction64420Result {
	one := qm31.One()

	constraint := qm31.Mul(dstBaseFP, qm31.Sub(one, dstBaseFP))
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	constraint = qm31.Mul(op0BaseFP, qm31.Sub(one, op0BaseFP))
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	constraint = qm31.Mul(op1BaseFP, qm31.Sub(one, op1BaseFP))
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	constraint = qm31.Mul(op1BaseAP, qm31.Sub(one, op1BaseAP))
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	constraint = qm31.Mul(apUpdateAdd1, qm31.Sub(one, apUpdateAdd1))
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	flags := qm31.Mul(dstBaseFP, qm31Const(8))
	flags = qm31.Add(flags, qm31.Mul(op0BaseFP, qm31Const(16)))
	flags = qm31.Add(flags, qm31.Mul(op1BaseFP, qm31Const(64)))
	flags = qm31.Add(flags, qm31.Mul(op1BaseAP, qm31Const(128)))

	beta := qm31.Mul(apUpdateAdd1, qm31Const(32))

	values := []m31.QM31{
		inputPC,
		offset0,
		offset1,
		offset2,
		flags,
		beta,
		opcodeExtension,
	}

	verifySum, err := qm31.Combine(verifyInstructionElements, values)
	if err != nil {
		panic(err)
	}

	base := qm31Const(32768)

	return DecodeInstruction64420Result{
		Offset0MinusBase: qm31.Sub(offset0, base),
		Offset1MinusBase: qm31.Sub(offset1, base),
		Offset2MinusBase: qm31.Sub(offset2, base),
		VerifySum:        verifySum,
		Sum:              sum,
	}
}
