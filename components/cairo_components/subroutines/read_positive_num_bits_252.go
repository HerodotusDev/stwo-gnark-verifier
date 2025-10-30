package subroutines

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

type ReadPositiveNumBits252Result struct {
	AddressLookupSum m31.QM31
	IdToBigLookupSum m31.QM31
}

func ReadPositiveNumBits252Evaluate(
	qm31 *m31.QM31Chip,
	input m31.QM31,
	id m31.QM31,
	limbs []m31.QM31,
	memoryAddressElements m31.InteractionElements,
	memoryIdToBigElements m31.InteractionElements,
) ReadPositiveNumBits252Result {
	if len(limbs) != 28 {
		panic("readPositiveNumBits252Evaluate expects 28 limbs")
	}

	addressLookupSum, err := qm31.Combine(memoryAddressElements, []m31.QM31{input, id})
	if err != nil {
		panic(err)
	}

	values := make([]m31.QM31, 0, 29)
	values = append(values, id)
	values = append(values, limbs...)

	idToBigLookupSum, err := qm31.Combine(memoryIdToBigElements, values)
	if err != nil {
		panic(err)
	}

	return ReadPositiveNumBits252Result{
		AddressLookupSum: addressLookupSum,
		IdToBigLookupSum: idToBigLookupSum,
	}
}
