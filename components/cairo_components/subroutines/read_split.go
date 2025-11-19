package subroutines

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

type ReadSplitResult struct {
	Sum                m31.QM31
	RangeCheckSum      m31.QM31
	AddressLookupSum   m31.QM31
	IdToBigLookupSum   m31.QM31
	MostSignificantRaw m31.QM31
}

func ReadSplitEvaluate(
	qm31 *m31.QM31Chip,
	address m31.QM31,
	valueLimbs []m31.QM31,
	msLimbLow m31.QM31,
	msLimbHigh m31.QM31,
	id m31.QM31,
	rangeCheckElements m31.InteractionElements,
	memoryAddressElements m31.InteractionElements,
	memoryIdElements m31.InteractionElements,
	sum m31.QM31,
	domainVanishInv m31.QM31,
	randomCoeff m31.QM31,
) ReadSplitResult {
	if len(valueLimbs) != 27 {
		panic("ReadSplitEvaluate expects 27 value limbs")
	}

	msCombined := qm31.Add(
		qm31.Mul(msLimbHigh, qm31Const(32)),
		msLimbLow,
	)

	rangeCheckSum, err := qm31.Combine(
		rangeCheckElements,
		[]m31.QM31{msLimbLow, msLimbHigh},
	)
	if err != nil {
		panic(err)
	}

	valueSlice := make([]m31.QM31, len(valueLimbs)+1)
	copy(valueSlice, valueLimbs)
	valueSlice[len(valueLimbs)] = msCombined

	memRes := MemVerifyEvaluate(
		qm31,
		address,
		valueSlice,
		id,
		memoryAddressElements,
		memoryIdElements,
		sum,
		domainVanishInv,
		randomCoeff,
	)
	sum = memRes.Sum

	return ReadSplitResult{
		Sum:                sum,
		RangeCheckSum:      rangeCheckSum,
		AddressLookupSum:   memRes.AddressLookupSum,
		IdToBigLookupSum:   memRes.IdToBigLookupSum,
		MostSignificantRaw: msCombined,
	}
}
