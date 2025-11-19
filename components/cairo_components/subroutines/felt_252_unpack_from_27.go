package subroutines

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

func Felt252UnpackFrom27Evaluate(
	qm31 *m31.QM31Chip,
	inputs [10]m31.QM31,
	lowLimbs [9]m31.QM31,
	highLimbs [9]m31.QM31,
) [10]m31.QM31 {
	constFactor := qm31Const(8192)
	scale := qm31Const(512)

	var result [10]m31.QM31
	for i := 0; i < 9; i++ {
		value := qm31.Sub(inputs[i], lowLimbs[i])
		value = qm31.Sub(value, qm31.Mul(highLimbs[i], scale))
		result[i] = qm31.Mul(value, constFactor)
	}
	result[9] = inputs[9]

	return result
}
