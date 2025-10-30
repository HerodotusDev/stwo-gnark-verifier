package subroutines

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

type ReadPositiveNumBits144Result struct {
	Sum              m31.QM31
	AddressLookupSum m31.QM31
	IdToBigLookupSum m31.QM31
}

func ReadPositiveNumBits144Evaluate(
	qm31 *m31.QM31Chip,
	input m31.QM31,
	id m31.QM31,
	limbs []m31.QM31,
	memoryAddressElements m31.InteractionElements,
	memoryIdToBigElements m31.InteractionElements,
	sum m31.QM31,
	_ m31.QM31,
	_ m31.QM31,
) ReadPositiveNumBits144Result {
	if len(limbs) != 16 {
		panic("readPositiveNumBits144Evaluate expects 16 limbs")
	}

	addressLookupSum, err := qm31.Combine(memoryAddressElements, []m31.QM31{input, id})
	if err != nil {
		panic(err)
	}

	values := make([]m31.QM31, 0, 29)
	values = append(values, id)
	values = append(values, limbs...)

	for len(values) < 29 {
		values = append(values, qm31Const(0))
	}

	idToBigLookupSum, err := qm31.Combine(memoryIdToBigElements, values)
	if err != nil {
		panic(err)
	}

	return ReadPositiveNumBits144Result{
		Sum:              sum,
		AddressLookupSum: addressLookupSum,
		IdToBigLookupSum: idToBigLookupSum,
	}
}
