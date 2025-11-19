package subroutines

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

func DecodeInstruction7EBC4Evaluate(
	qm31 *m31.QM31Chip,
	inputPC m31.QM31,
	apUpdateAdd1 m31.QM31,
	verifyInstructionElements m31.InteractionElements,
	sum m31.QM31,
	domainVanishInv m31.QM31,
	randomCoeff m31.QM31,
) (m31.QM31, m31.QM31) {
	one := qm31.One()

	// ap_update_add_1 is a bit.
	constraint := qm31.Mul(apUpdateAdd1, qm31.Sub(one, apUpdateAdd1))
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	values := []m31.QM31{
		inputPC,
		qm31Const(32767),
		qm31Const(32767),
		qm31Const(32769),
		qm31Const(56),
		qm31.Add(qm31Const(4), qm31.Mul(apUpdateAdd1, qm31Const(32))),
		qm31Const(0),
	}

	var err error
	verifySum, err := qm31.Combine(verifyInstructionElements, values)
	if err != nil {
		panic(err)
	}

	return verifySum, sum
}
