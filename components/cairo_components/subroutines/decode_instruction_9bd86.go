package subroutines

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

type DecodeInstruction9BD86Result struct {
	Offset1MinusBase m31.QM31
	Offset2MinusBase m31.QM31
	VerifySum        m31.QM31
	Sum              m31.QM31
}

func DecodeInstruction9BD86Evaluate(
	qm31 *m31.QM31Chip,
	inputPC m31.QM31,
	offset1 m31.QM31,
	offset2 m31.QM31,
	op0BaseFP m31.QM31,
	apUpdateAdd1 m31.QM31,
	verifyInstructionElements m31.InteractionElements,
	sum m31.QM31,
	domainVanishInv m31.QM31,
	randomCoeff m31.QM31,
) DecodeInstruction9BD86Result {
	one := qm31.One()

	// op0_base_fp is a bit.
	constraint := qm31.Mul(op0BaseFP, qm31.Sub(one, op0BaseFP))
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	// ap_update_add_1 is a bit.
	constraint = qm31.Mul(apUpdateAdd1, qm31.Sub(one, apUpdateAdd1))
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	alpha := qm31.Add(qm31Const(8), qm31.Mul(op0BaseFP, qm31Const(16)))
	beta := qm31.Add(qm31Const(2), qm31.Mul(apUpdateAdd1, qm31Const(32)))

	values := []m31.QM31{
		inputPC,
		qm31Const(32767),
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

	return DecodeInstruction9BD86Result{
		Offset1MinusBase: qm31.Sub(offset1, qm31Const(32768)),
		Offset2MinusBase: qm31.Sub(offset2, qm31Const(32768)),
		VerifySum:        verifySum,
		Sum:              sum,
	}
}
