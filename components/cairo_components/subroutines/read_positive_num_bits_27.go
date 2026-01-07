package subroutines

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

type ReadPositiveNumBits27Result struct {
	AddressLookupSum m31.QM31
	IdToBigLookupSum m31.QM31
}

func ReadPositiveNumBits27Evaluate(
	qm31 *m31.QM31Chip,
	input m31.QM31,
	id m31.QM31,
	limb0 m31.QM31,
	limb1 m31.QM31,
	limb2 m31.QM31,
	memoryAddressElements m31.InteractionElements,
	memoryIDToBigElements m31.InteractionElements,
) ReadPositiveNumBits27Result {
	var err error

	addressLookupSum, err := qm31.Combine(memoryAddressElements, []m31.QM31{input, id})
	if err != nil {
		panic(err)
	}

	values := []m31.QM31{
		id,
		limb0,
		limb1,
		limb2,
	}

	// Pad with zeros up to 29 entries (id + 28 limbs) to match Cairo table width.
	for len(values) < 29 {
		values = append(values, qm31Const(0))
	}

	idToBigLookupSum, err := qm31.Combine(memoryIDToBigElements, values)
	if err != nil {
		panic(err)
	}

	return ReadPositiveNumBits27Result{
		AddressLookupSum: addressLookupSum,
		IdToBigLookupSum: idToBigLookupSum,
	}
}
