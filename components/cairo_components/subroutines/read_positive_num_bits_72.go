package subroutines

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

type ReadPositiveNumBits72Result struct {
	Sum              m31.QM31
	AddressLookupSum m31.QM31
	IdToBigLookupSum m31.QM31
}

func ReadPositiveNumBits72Evaluate(
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
	memoryAddressElements m31.InteractionElements,
	memoryIdToBigElements m31.InteractionElements,
	sum m31.QM31,
	_ m31.QM31,
	_ m31.QM31,
) ReadPositiveNumBits72Result {
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
		limb4,
		limb5,
		limb6,
		limb7,
	}

	for len(values) < 29 {
		values = append(values, qm31Const(0))
	}

	idToBigLookupSum, err := qm31.Combine(memoryIdToBigElements, values)
	if err != nil {
		panic(err)
	}

	return ReadPositiveNumBits72Result{
		Sum:              sum,
		AddressLookupSum: addressLookupSum,
		IdToBigLookupSum: idToBigLookupSum,
	}
}
