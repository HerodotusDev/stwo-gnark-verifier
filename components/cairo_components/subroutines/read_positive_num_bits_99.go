package subroutines

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

type ReadPositiveNumBits99Result struct {
	Sum              m31.QM31
	AddressLookupSum m31.QM31
	IdToBigLookupSum m31.QM31
}

func ReadPositiveNumBits99Evaluate(
	qm31 *m31.QM31Chip,
	address m31.QM31,
	id m31.QM31,
	limbs [11]m31.QM31,
	memoryAddressElements m31.InteractionElements,
	memoryIdElements m31.InteractionElements,
	sum m31.QM31,
	_ m31.QM31,
	_ m31.QM31,
) ReadPositiveNumBits99Result {
	addressSum, err := qm31.Combine(
		memoryAddressElements,
		[]m31.QM31{address, id},
	)
	if err != nil {
		panic(err)
	}

	values := make([]m31.QM31, 29)
	// Pre-fill the 29-slot lookup vector, avoiding nil QM31 limbs during dummy runs
	for i := range values {
		values[i] = m31.NewQM31Unchecked(0, 0, 0, 0)
	}
	values[0] = id
	for i := 0; i < len(limbs); i++ {
		values[i+1] = limbs[i]
	}

	idSum, err := qm31.Combine(memoryIdElements, values)
	if err != nil {
		panic(err)
	}

	return ReadPositiveNumBits99Result{
		Sum:              sum,
		AddressLookupSum: addressSum,
		IdToBigLookupSum: idSum,
	}
}
