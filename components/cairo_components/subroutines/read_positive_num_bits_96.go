package subroutines

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

type ReadPositiveNumBits96Result struct {
	Sum              m31.QM31
	AddressLookupSum m31.QM31
	RangeCheck6Sum   m31.QM31
	IdToBigLookupSum m31.QM31
}

func ReadPositiveNumBits96Evaluate(
	qm31 *m31.QM31Chip,
	input m31.QM31,
	id m31.QM31,
	limb0 m31.QM31,
	limb1 m31.QM31,
	limb2 m31.QM31,
	limb3 m31.QM31,
	limb4 m31.QM31,
	limb5 m31.QM31,
	limb6 m31.QM31,
	limb7 m31.QM31,
	limb8 m31.QM31,
	limb9 m31.QM31,
	limb10 m31.QM31,
	memoryAddressElements m31.InteractionElements,
	rangeCheck6Elements m31.InteractionElements,
	memoryIDToBigElements m31.InteractionElements,
	sum m31.QM31,
	domainVanishInv m31.QM31,
	randomCoeff m31.QM31,
) ReadPositiveNumBits96Result {
	addressLookupSum, err := qm31.Combine(memoryAddressElements, []m31.QM31{input, id})
	if err != nil {
		panic(err)
	}

	rangeCheckRes := RangeCheckLastLimbBitsInMsLimb6Evaluate(
		qm31,
		limb10,
		rangeCheck6Elements,
		sum,
		domainVanishInv,
		randomCoeff,
	)
	sum = rangeCheckRes.Sum

	values := []m31.QM31{
		id,
		limb0,
		limb1,
		limb2,
		limb3,
		limb4,
		limb5,
		limb6,
		limb7,
		limb8,
		limb9,
		limb10,
	}
	for len(values) < 29 {
		values = append(values, qm31Const(0))
	}

	idToBigLookupSum, err := qm31.Combine(memoryIDToBigElements, values)
	if err != nil {
		panic(err)
	}

	return ReadPositiveNumBits96Result{
		Sum:              sum,
		AddressLookupSum: addressLookupSum,
		RangeCheck6Sum:   rangeCheckRes.RangeCheck6Sum,
		IdToBigLookupSum: idToBigLookupSum,
	}
}
