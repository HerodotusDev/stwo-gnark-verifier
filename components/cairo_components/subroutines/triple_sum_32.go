package subroutines

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
)

type TripleSum32Inputs struct {
	A0 m31.QM31
	A1 m31.QM31
	B0 m31.QM31
	B1 m31.QM31
	C0 m31.QM31
	C1 m31.QM31
}

func TripleSum32Evaluate(
	qm31 *m31.QM31Chip,
	inputs TripleSum32Inputs,
	res0 m31.QM31,
	res1 m31.QM31,
	sum m31.QM31,
	vanishEvalInv m31.QM31,
	randomCoeff m31.QM31,
) m31.QM31 {
	carryLow := qm31.Sub(
		qm31.Add(
			qm31.Add(inputs.A0, inputs.B0),
			inputs.C0,
		),
		res0,
	)
	carryLow = qm31.Mul(carryLow, qm31Const(32768))

	constraint := qm31.Mul(
		carryLow,
		qm31.Mul(
			qm31.Sub(carryLow, qm31Const(1)),
			qm31.Sub(carryLow, qm31Const(2)),
		),
	)
	constraint = qm31.Mul(constraint, vanishEvalInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	carryHigh := qm31.Sub(
		qm31.Add(
			qm31.Add(
				qm31.Add(inputs.A1, inputs.B1),
				inputs.C1,
			),
			carryLow,
		),
		res1,
	)
	carryHigh = qm31.Mul(carryHigh, qm31Const(32768))

	constraint = qm31.Mul(
		carryHigh,
		qm31.Mul(
			qm31.Sub(carryHigh, qm31Const(1)),
			qm31.Sub(carryHigh, qm31Const(2)),
		),
	)
	constraint = qm31.Mul(constraint, vanishEvalInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	return sum
}
