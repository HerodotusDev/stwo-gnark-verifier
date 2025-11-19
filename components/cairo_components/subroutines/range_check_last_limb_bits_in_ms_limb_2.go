package subroutines

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

type RangeCheckLastLimbBitsInMsLimb2Result struct {
	Sum m31.QM31
}

func RangeCheckLastLimbBitsInMsLimb2Evaluate(
	qm31 *m31.QM31Chip,
	input m31.QM31,
	msb m31.QM31,
	sum m31.QM31,
	domainVanishInv m31.QM31,
	randomCoeff m31.QM31,
) RangeCheckLastLimbBitsInMsLimb2Result {
	one := qm31.One()

	constraint := qm31.Mul(msb, qm31.Sub(one, msb))
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	bitBeforeMsb := qm31.Sub(input, qm31.Mul(msb, qm31Const(2)))
	constraint = qm31.Mul(bitBeforeMsb, qm31.Sub(one, bitBeforeMsb))
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	return RangeCheckLastLimbBitsInMsLimb2Result{Sum: sum}
}
