package subroutines

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

type MemCondVerifyEqualKnownIDResult struct {
	Sum              m31.QM31
	AddressLookupSum m31.QM31
}

func MemCondVerifyEqualKnownIDEvaluate(
	qm31 *m31.QM31Chip,
	address m31.QM31,
	id m31.QM31,
	condition m31.QM31,
	knownID m31.QM31,
	memoryAddressElements m31.InteractionElements,
	sum m31.QM31,
	domainVanishInv m31.QM31,
	randomCoeff m31.QM31,
) MemCondVerifyEqualKnownIDResult {
	addressSum, err := qm31.Combine(
		memoryAddressElements,
		[]m31.QM31{address, knownID},
	)
	if err != nil {
		panic(err)
	}

	constraint := qm31.Mul(qm31.Sub(knownID, id), condition)
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	return MemCondVerifyEqualKnownIDResult{
		Sum:              sum,
		AddressLookupSum: addressSum,
	}
}
