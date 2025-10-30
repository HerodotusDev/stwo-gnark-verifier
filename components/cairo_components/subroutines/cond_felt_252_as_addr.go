package subroutines

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

type CondFelt252AsAddrResult struct {
	Sum  m31.QM31
	Addr m31.QM31
}

func CondFelt252AsAddrEvaluate(
	qm31 *m31.QM31Chip,
	limbs []m31.QM31,
	sum m31.QM31,
	domainVanishInv m31.QM31,
	randomCoeff m31.QM31,
) CondFelt252AsAddrResult {
	if len(limbs) != 29 {
		panic("CondFelt252AsAddrEvaluate expects 29 limbs")
	}

	enabler := limbs[28]
	for i := 3; i < 28; i++ {
		constraint := qm31.Mul(enabler, limbs[i])
		constraint = qm31.Mul(constraint, domainVanishInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	addr := limbs[0]
	addr = qm31.Add(addr, qm31.Mul(limbs[1], qm31Const(512)))
	addr = qm31.Add(addr, qm31.Mul(limbs[2], qm31Const(262144)))

	return CondFelt252AsAddrResult{
		Sum:  sum,
		Addr: addr,
	}
}
