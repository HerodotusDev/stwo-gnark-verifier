package subroutines

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

func DecodeInstruction15A61Evaluate(
	qm31 *m31.QM31Chip,
	inputPC m31.QM31,
	verifyInstructionElements m31.InteractionElements,
) m31.QM31 {
	values := []m31.QM31{
		inputPC,
		qm31Const(32766),
		qm31Const(32767),
		qm31Const(32767),
		qm31Const(88),
		qm31Const(130),
		qm31Const(0),
	}

	var err error
	verifySum, err := qm31.Combine(verifyInstructionElements, values)
	if err != nil {
		panic(err)
	}

	return verifySum
}
