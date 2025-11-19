package subroutines

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

type CondFelt252AsRelImmResult struct {
	Sum    m31.QM31
	RelImm m31.QM31
}

func CondFelt252AsRelImmEvaluate(
	qm31 *m31.QM31Chip,
	limbs []m31.QM31,
	msb m31.QM31,
	midLimbsSet m31.QM31,
	sum m31.QM31,
	domainVanishInv m31.QM31,
	randomCoeff m31.QM31,
) CondFelt252AsRelImmResult {
	if len(limbs) != 29 {
		panic("CondFelt252AsRelImmEvaluate expects 29 limbs")
	}

	sum = CondDecodeSmallSignEvaluate(
		qm31,
		limbs[28],
		msb,
		midLimbsSet,
		sum,
		domainVanishInv,
		randomCoeff,
	)

	enabler := limbs[28]
	scale511 := qm31Const(511)
	for i := 3; i <= 20; i++ {
		target := qm31.Mul(midLimbsSet, scale511)
		constraint := qm31.Mul(enabler, qm31.Sub(limbs[i], target))
		constraint = qm31.Mul(constraint, domainVanishInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	scale136 := qm31Const(136)
	constraint := qm31.Mul(
		enabler,
		qm31.Sub(
			limbs[21],
			qm31.Sub(qm31.Mul(scale136, msb), midLimbsSet),
		),
	)
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	for i := 22; i <= 26; i++ {
		constraint = qm31.Mul(enabler, limbs[i])
		constraint = qm31.Mul(constraint, domainVanishInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	scale256 := qm31Const(256)
	constraint = qm31.Mul(enabler, qm31.Sub(limbs[27], qm31.Mul(msb, scale256)))
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	relImm := limbs[0]
	relImm = qm31.Add(relImm, qm31.Mul(limbs[1], qm31Const(512)))
	relImm = qm31.Add(relImm, qm31.Mul(limbs[2], qm31Const(262144)))
	relImm = qm31.Sub(relImm, msb)
	relImm = qm31.Sub(relImm, qm31.Mul(midLimbsSet, qm31Const(134217728)))

	return CondFelt252AsRelImmResult{
		Sum:    sum,
		RelImm: relImm,
	}
}
