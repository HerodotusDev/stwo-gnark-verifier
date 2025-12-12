package subroutines

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

type ReadPositiveNumBits36Result struct {
	Sum              m31.QM31
	AddressLookupSum m31.QM31
	IdToBigLookupSum m31.QM31
}

func ReadPositiveNumBits36Evaluate(
	qm31 *m31.QM31Chip,
	input m31.QM31,
	id m31.QM31,
	limb0 m31.QM31,
	limb1 m31.QM31,
	limb2 m31.QM31,
	limb3 m31.QM31,
	memoryAddressElements m31.InteractionElements,
	memoryIDToBigElements m31.InteractionElements,
	sum m31.QM31,
	_ m31.QM31,
	_ m31.QM31,
) ReadPositiveNumBits36Result {
	addressLookupSum, err := qm31.Combine(memoryAddressElements, []m31.QM31{input, id})
	if err != nil {
		panic(err)
	}

	values := []m31.QM31{
		id,
		limb0,
		limb1,
		limb2,
		limb3,
	}

	for len(values) < 29 {
		values = append(values, qm31Const(0))
	}

	idToBigLookupSum, err := qm31.Combine(memoryIDToBigElements, values)
	if err != nil {
		panic(err)
	}

	return ReadPositiveNumBits36Result{
		Sum:              sum,
		AddressLookupSum: addressLookupSum,
		IdToBigLookupSum: idToBigLookupSum,
	}
}
