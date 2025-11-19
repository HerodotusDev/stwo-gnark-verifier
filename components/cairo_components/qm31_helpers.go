package cairo_components

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

func qm31Const(value uint64) m31.QM31 {
	return m31.NewQM31Unchecked(value, 0, 0, 0)
}

func accumulateConstraint(qm31 *m31.QM31Chip, sum, randomCoeff, constraint m31.QM31) m31.QM31 {
	return qm31.Add(qm31.Mul(sum, randomCoeff), constraint)
}
