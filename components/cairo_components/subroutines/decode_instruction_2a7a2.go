package subroutines

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

func DecodeInstruction2A7A2Evaluate(
	qm31 *m31.QM31Chip,
	inputPC m31.QM31,
	verifyInstructionElements m31.InteractionElements,
) m31.QM31 {
	values := []m31.QM31{
		inputPC,
		qm31Const(32768),
		qm31Const(32769),
		qm31Const(32769),
		qm31Const(32),
		qm31Const(68),
		qm31Const(0),
	}

	var err error
	verifySum, err := qm31.Combine(verifyInstructionElements, values)
	if err != nil {
		panic(err)
	}

	return verifySum
}
