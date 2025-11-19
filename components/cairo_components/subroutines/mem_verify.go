package subroutines

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

type MemVerifyResult struct {
	AddressLookupSum m31.QM31
	IdToBigLookupSum m31.QM31
	Sum              m31.QM31
}

func MemVerifyEvaluate(
	qm31 *m31.QM31Chip,
	address m31.QM31,
	valueLimbs []m31.QM31,
	id m31.QM31,
	memoryAddressToIdElements m31.InteractionElements,
	memoryIdToBigElements m31.InteractionElements,
	sum m31.QM31,
	_ m31.QM31,
	_ m31.QM31,
) MemVerifyResult {
	if len(valueLimbs) != 28 {
		panic("MemVerifyEvaluate expects 28 value limbs")
	}

	addressSum, err := qm31.Combine(
		memoryAddressToIdElements,
		[]m31.QM31{address, id},
	)
	if err != nil {
		panic(err)
	}

	values := make([]m31.QM31, 1+len(valueLimbs))
	values[0] = id
	copy(values[1:], valueLimbs)

	idToBigSum, err := qm31.Combine(memoryIdToBigElements, values)
	if err != nil {
		panic(err)
	}

	return MemVerifyResult{
		AddressLookupSum: addressSum,
		IdToBigLookupSum: idToBigSum,
		Sum:              sum,
	}
}
