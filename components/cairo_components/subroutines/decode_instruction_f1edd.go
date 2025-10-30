package subroutines

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

type DecodeInstructionF1EDDResult struct {
	Offset2MinusBase m31.QM31
	Op1BaseAP        m31.QM31
	VerifySum        m31.QM31
	Sum              m31.QM31
}

func DecodeInstructionF1EDDEvaluate(
	qm31 *m31.QM31Chip,
	inputPC m31.QM31,
	offset2 m31.QM31,
	op1BaseFP m31.QM31,
	verifyInstructionElements m31.InteractionElements,
	sum m31.QM31,
	domainVanishInv m31.QM31,
	randomCoeff m31.QM31,
) DecodeInstructionF1EDDResult {
	one := qm31.One()

	// op1_base_fp is a bit.
	constraint := qm31.Mul(op1BaseFP, qm31.Sub(one, op1BaseFP))
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	op1BaseAP := qm31.Sub(one, op1BaseFP)

	alpha := qm31.Add(
		qm31.Mul(op1BaseFP, qm31Const(64)),
		qm31.Mul(op1BaseAP, qm31Const(128)),
	)

	values := []m31.QM31{
		inputPC,
		qm31Const(32768),
		qm31Const(32769),
		offset2,
		alpha,
		qm31Const(66),
		qm31Const(0),
	}

	var err error
	verifySum, err := qm31.Combine(verifyInstructionElements, values)
	if err != nil {
		panic(err)
	}

	return DecodeInstructionF1EDDResult{
		Offset2MinusBase: qm31.Sub(offset2, qm31Const(32768)),
		Op1BaseAP:        op1BaseAP,
		VerifySum:        verifySum,
		Sum:              sum,
	}
}
