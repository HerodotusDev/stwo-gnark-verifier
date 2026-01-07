package subroutines

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

type EncodeOffsetsResult struct {
	Offset1Combined m31.QM31
	Offset2Combined m31.QM31
	Range725Sum     m31.QM31
	Range43Sum      m31.QM31
	Sum             m31.QM31
}

func EncodeOffsetsEvaluate(
	qm31 *m31.QM31Chip,
	offset0 m31.QM31,
	offset1 m31.QM31,
	offset2 m31.QM31,
	offset0Low m31.QM31,
	offset0Mid m31.QM31,
	offset1Low m31.QM31,
	offset1Mid m31.QM31,
	offset1High m31.QM31,
	offset2Low m31.QM31,
	offset2Mid m31.QM31,
	offset2High m31.QM31,
	range725Elements m31.InteractionElements,
	range43Elements m31.InteractionElements,
	sum m31.QM31,
	domainVanishInv m31.QM31,
	randomCoeff m31.QM31,
) EncodeOffsetsResult {
	reconstructed0 := qm31.Add(offset0Low, qm31.Mul(offset0Mid, qm31Const(512)))
	constraint := qm31.Sub(reconstructed0, offset0)
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	reconstructed1 := qm31.Add(
		qm31.Add(offset1Low, qm31.Mul(offset1Mid, qm31Const(4))),
		qm31.Mul(offset1High, qm31Const(2048)),
	)
	constraint = qm31.Sub(reconstructed1, offset1)
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	reconstructed2 := qm31.Add(
		qm31.Add(offset2Low, qm31.Mul(offset2Mid, qm31Const(16))),
		qm31.Mul(offset2High, qm31Const(8192)),
	)
	constraint = qm31.Sub(reconstructed2, offset2)
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	range7Sum, err := qm31.Combine(
		range725Elements,
		[]m31.QM31{offset0Mid, offset1Low, offset1High},
	)
	if err != nil {
		panic(err)
	}

	range4Sum, err := qm31.Combine(
		range43Elements,
		[]m31.QM31{offset2Low, offset2High},
	)
	if err != nil {
		panic(err)
	}

	return EncodeOffsetsResult{
		Offset1Combined: qm31.Add(offset0Mid, qm31.Mul(offset1Low, qm31Const(128))),
		Offset2Combined: qm31.Add(offset1High, qm31.Mul(offset2Low, qm31Const(32))),
		Range725Sum:     range7Sum,
		Range43Sum:      range4Sum,
		Sum:             sum,
	}
}
