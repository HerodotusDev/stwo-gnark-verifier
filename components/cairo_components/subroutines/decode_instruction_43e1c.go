package subroutines

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

type DecodeInstruction43E1CResult struct {
	Offset2MinusBase m31.QM31
	VerifySum        m31.QM31
	Sum              m31.QM31
}

func DecodeInstruction43E1CEvaluate(
	qm31 *m31.QM31Chip,
	inputPC m31.QM31,
	offset2 m31.QM31,
	op1BaseFP m31.QM31,
	op1BaseAP m31.QM31,
	apUpdateAdd1 m31.QM31,
	verifyInstructionElements m31.InteractionElements,
	sum m31.QM31,
	domainVanishInv m31.QM31,
	randomCoeff m31.QM31,
) DecodeInstruction43E1CResult {
	one := qm31.One()

	// op1_base_fp is a bit.
	constraint := qm31.Mul(op1BaseFP, qm31.Sub(one, op1BaseFP))
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	// op1_base_ap is a bit.
	constraint = qm31.Mul(op1BaseAP, qm31.Sub(one, op1BaseAP))
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	// ap_update_add_1 is a bit.
	constraint = qm31.Mul(apUpdateAdd1, qm31.Sub(one, apUpdateAdd1))
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	alpha := qm31.Add(qm31Const(24), qm31.Mul(op1BaseFP, qm31Const(64)))
	alpha = qm31.Add(alpha, qm31.Mul(op1BaseAP, qm31Const(128)))

	beta := qm31.Add(qm31Const(2), qm31.Mul(apUpdateAdd1, qm31Const(32)))

	values := []m31.QM31{
		inputPC,
		qm31Const(32767),
		qm31Const(32767),
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

	return DecodeInstruction43E1CResult{
		Offset2MinusBase: qm31.Sub(offset2, qm31Const(32768)),
		VerifySum:        verifySum,
		Sum:              sum,
	}
}
