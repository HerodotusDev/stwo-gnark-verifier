package subroutines

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
)

func CondDecodeSmallSignEvaluate(
	qm31 *m31.QM31Chip,
	input m31.QM31,
	msb m31.QM31,
	midLimbsSet m31.QM31,
	sum m31.QM31,
	domainVanishInv m31.QM31,
	randomCoeff m31.QM31,
) m31.QM31 {
	one := qm31.One()

	// Constraint - msb is a bit.
	constraint := qm31.Mul(msb, qm31.Sub(msb, one))
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	// Constraint - mid_limbs_set is a bit.
	constraint = qm31.Mul(midLimbsSet, qm31.Sub(midLimbsSet, one))
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	// Constraint - cannot have msb == 0 and mid_limbs_set == 1.
	constraint = qm31.Mul(qm31.Mul(input, midLimbsSet), qm31.Sub(msb, one))
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	return sum
}
