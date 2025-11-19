package subroutines

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

func qm31Const(value uint64) m31.QM31 {
	return m31.NewQM31Unchecked(value, 0, 0, 0)
}

func accumulateConstraint(qm31 *m31.QM31Chip, sum, randomCoeff, constraint m31.QM31) m31.QM31 {
	return qm31.Add(qm31.Mul(sum, randomCoeff), constraint)
}

func enforceCubicConstraint(
	qm31 *m31.QM31Chip,
	sum m31.QM31,
	randomCoeff m31.QM31,
	vanishEvalInv m31.QM31,
	value m31.QM31,
) m31.QM31 {
	cubic := qm31.Mul(value, qm31.Mul(value, value))
	constraint := qm31.Sub(cubic, value)
	constraint = qm31.Mul(constraint, vanishEvalInv)
	return accumulateConstraint(qm31, sum, randomCoeff, constraint)
}
