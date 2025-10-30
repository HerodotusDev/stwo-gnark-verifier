package subroutines

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

func VerifyAdd252Evaluate(
	qm31 *m31.QM31Chip,
	aLimbs []m31.QM31,
	bLimbs []m31.QM31,
	cLimbs []m31.QM31,
	subPBit m31.QM31,
	sum m31.QM31,
	domainVanishInv m31.QM31,
	randomCoeff m31.QM31,
) m31.QM31 {
	if len(aLimbs) != 28 || len(bLimbs) != 28 || len(cLimbs) != 28 {
		panic("VerifyAdd252Evaluate expects 28 limbs for each operand")
	}

	one := qm31.One()
	scale := qm31Const(4194304)

	// sub_p_bit is a bit.
	constraint := qm31.Mul(subPBit, qm31.Sub(subPBit, one))
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	var carry m31.QM31

	// limb 0
	expr := qm31.Sub(qm31.Sub(qm31.Add(aLimbs[0], bLimbs[0]), cLimbs[0]), subPBit)
	carry = qm31.Mul(expr, scale)
	sum = enforceCarryConstraint(qm31, carry, sum, domainVanishInv, randomCoeff)

	for i := 1; i < 21; i++ {
		expr = qm31.Sub(qm31.Add(qm31.Add(aLimbs[i], bLimbs[i]), carry), cLimbs[i])
		carry = qm31.Mul(expr, scale)
		sum = enforceCarryConstraint(qm31, carry, sum, domainVanishInv, randomCoeff)
	}

	// limb 21 has extra subtraction with 136 * sub_p_bit.
	expr = qm31.Sub(
		qm31.Sub(
			qm31.Add(qm31.Add(aLimbs[21], bLimbs[21]), carry),
			cLimbs[21],
		),
		qm31.Mul(qm31Const(136), subPBit),
	)
	carry = qm31.Mul(expr, scale)
	sum = enforceCarryConstraint(qm31, carry, sum, domainVanishInv, randomCoeff)

	for i := 22; i <= 26; i++ {
		expr = qm31.Sub(qm31.Add(qm31.Add(aLimbs[i], bLimbs[i]), carry), cLimbs[i])
		carry = qm31.Mul(expr, scale)
		sum = enforceCarryConstraint(qm31, carry, sum, domainVanishInv, randomCoeff)
	}

	// limb 27 final constraint.
	expr = qm31.Sub(
		qm31.Sub(
			qm31.Add(qm31.Add(aLimbs[27], bLimbs[27]), carry),
			cLimbs[27],
		),
		qm31.Mul(qm31Const(256), subPBit),
	)
	constraint = qm31.Mul(expr, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	return sum
}

func enforceCarryConstraint(
	qm31 *m31.QM31Chip,
	carry m31.QM31,
	sum m31.QM31,
	domainVanishInv m31.QM31,
	randomCoeff m31.QM31,
) m31.QM31 {
	square := qm31.Mul(carry, carry)
	constraint := qm31.Mul(carry, qm31.Sub(square, qm31.One()))
	constraint = qm31.Mul(constraint, domainVanishInv)
	return accumulateConstraint(qm31, sum, randomCoeff, constraint)
}
