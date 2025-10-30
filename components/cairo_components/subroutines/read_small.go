package subroutines

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

type ReadSmallResult struct {
	Value            m31.QM31
	AddressLookupSum m31.QM31
	IdToBigLookupSum m31.QM31
	Sum              m31.QM31
}

func ReadSmallEvaluate(
	qm31 *m31.QM31Chip,
	input m31.QM31,
	id m31.QM31,
	msb m31.QM31,
	midLimbsSet m31.QM31,
	limb0 m31.QM31,
	limb1 m31.QM31,
	limb2 m31.QM31,
	memoryAddressElements m31.InteractionElements,
	memoryIdToBigElements m31.InteractionElements,
	sum m31.QM31,
	domainVanishInv m31.QM31,
	randomCoeff m31.QM31,
) ReadSmallResult {
	addressLookupSum, err := qm31.Combine(memoryAddressElements, []m31.QM31{input, id})
	if err != nil {
		panic(err)
	}

	sum = CondDecodeSmallSignEvaluate(
		qm31,
		qm31Const(1),
		msb,
		midLimbsSet,
		sum,
		domainVanishInv,
		randomCoeff,
	)

	qm31511 := qm31Const(511)
	msbContribution := qm31.Mul(msb, qm31Const(256))
	midScaled := qm31.Mul(midLimbsSet, qm31511)

	values := []m31.QM31{
		id,
		limb0,
		limb1,
		limb2,
		midScaled,
		midScaled,
		midScaled,
		midScaled,
		midScaled,
		midScaled,
		midScaled,
		midScaled,
		midScaled,
		midScaled,
		midScaled,
		midScaled,
		midScaled,
		midScaled,
		midScaled,
		midScaled,
		midScaled,
		midScaled,
		qm31.Sub(qm31.Mul(qm31Const(136), msb), midLimbsSet),
		qm31Const(0),
		qm31Const(0),
		qm31Const(0),
		qm31Const(0),
		qm31Const(0),
		msbContribution,
	}

	idToBigLookupSum, err := qm31.Combine(memoryIdToBigElements, values)
	if err != nil {
		panic(err)
	}

	value := qm31.Add(
		qm31.Sub(
			qm31.Add(
				limb0,
				qm31.Mul(limb1, qm31Const(512)),
			),
			msb,
		),
		qm31.Mul(limb2, qm31Const(262144)),
	)
	value = qm31.Sub(value, qm31.Mul(midLimbsSet, qm31Const(134217728)))

	return ReadSmallResult{
		Value:            value,
		AddressLookupSum: addressLookupSum,
		IdToBigLookupSum: idToBigLookupSum,
		Sum:              sum,
	}
}
