package subroutines

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

type MemVerifyEqualResult struct {
	AddressLookupSum1 m31.QM31
	AddressLookupSum2 m31.QM31
	Sum               m31.QM31
}

func MemVerifyEqualEvaluate(
	qm31 *m31.QM31Chip,
	address1 m31.QM31,
	address2 m31.QM31,
	id m31.QM31,
	memoryAddressToIDElements m31.InteractionElements,
	sum m31.QM31,
) MemVerifyEqualResult {
	var err error

	AddressLookupSum1, err := qm31.Combine(memoryAddressToIDElements, []m31.QM31{address1, id})
	if err != nil {
		panic(err)
	}

	AddressLookupSum2, err := qm31.Combine(memoryAddressToIDElements, []m31.QM31{address2, id})
	if err != nil {
		panic(err)
	}

	return MemVerifyEqualResult{
		AddressLookupSum1: AddressLookupSum1,
		AddressLookupSum2: AddressLookupSum2,
		Sum:               sum,
	}
}
