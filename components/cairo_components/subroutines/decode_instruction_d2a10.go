package subroutines

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

type DecodeInstructionD2A10Result struct {
	Offset2MinusBase m31.QM31
	Op1BaseAP        m31.QM31
	VerifySum        m31.QM31
	Sum              m31.QM31
}

func DecodeInstructionD2A10Evaluate(
	qm31 *m31.QM31Chip,
	inputPC m31.QM31,
	offset2 m31.QM31,
	op1Imm m31.QM31,
	op1BaseFP m31.QM31,
	verifyInstructionElements m31.InteractionElements,
	sum m31.QM31,
	domainVanishInv m31.QM31,
	randomCoeff m31.QM31,
) DecodeInstructionD2A10Result {
	one := qm31.One()

	// Flag op1_imm is a bit.
	constraint := qm31.Mul(op1Imm, qm31.Sub(one, op1Imm))
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	// Flag op1_base_fp is a bit.
	constraint = qm31.Mul(op1BaseFP, qm31.Sub(one, op1BaseFP))
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	// Flag op1_base_ap is a bit.
	op1BaseAP := qm31.Sub(qm31.Sub(one, op1Imm), op1BaseFP)
	constraint = qm31.Mul(op1BaseAP, qm31.Sub(one, op1BaseAP))
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	offset2MinusBase := qm31.Sub(offset2, qm31Const(32768))

	alphaTerm := qm31.Add(qm31Const(24), qm31.Mul(op1Imm, qm31Const(32)))
	alphaTerm = qm31.Add(alphaTerm, qm31.Mul(op1BaseFP, qm31Const(64)))
	alphaTerm = qm31.Add(alphaTerm, qm31.Mul(op1BaseAP, qm31Const(128)))

	values := []m31.QM31{
		inputPC,
		qm31Const(32767),
		qm31Const(32767),
		offset2,
		alphaTerm,
		qm31Const(16),
		qm31Const(0),
	}

	var err error
	verifySum, err := qm31.Combine(verifyInstructionElements, values)
	if err != nil {
		panic(err)
	}

	return DecodeInstructionD2A10Result{
		Offset2MinusBase: offset2MinusBase,
		Op1BaseAP:        op1BaseAP,
		VerifySum:        verifySum,
		Sum:              sum,
	}
}
