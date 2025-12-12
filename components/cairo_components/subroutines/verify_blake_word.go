package subroutines

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

type VerifyBlakeWordResult struct {
	Sum              m31.QM31
	RangeCheckSum    m31.QM31
	AddressLookupSum m31.QM31
	IdToBigLookupSum m31.QM31
}

func VerifyBlakeWordEvaluate(
	qm31 *m31.QM31Chip,
	input [3]m31.QM31,
	low7MSBits m31.QM31,
	high14MSBits m31.QM31,
	high5MSBits m31.QM31,
	id m31.QM31,
	rangeCheckElements m31.InteractionElements,
	memoryAddressElements m31.InteractionElements,
	memoryIDElements m31.InteractionElements,
	sum m31.QM31,
	domainVanishInv m31.QM31,
	randomCoeff m31.QM31,
) VerifyBlakeWordResult {
	midBits := qm31.Sub(input[2], qm31.Mul(high14MSBits, qm31Const(4)))

	rangeCheckSum, err := qm31.Combine(
		rangeCheckElements,
		[]m31.QM31{low7MSBits, midBits, high5MSBits},
	)
	if err != nil {
		panic(err)
	}

	val0 := qm31.Sub(input[1], qm31.Mul(low7MSBits, qm31Const(512)))
	val1 := qm31.Add(low7MSBits, qm31.Mul(midBits, qm31Const(128)))
	val2 := qm31.Sub(high14MSBits, qm31.Mul(high5MSBits, qm31Const(512)))
	val3 := high5MSBits

	valueLimbs := make([]m31.QM31, 28)
	valueLimbs[0] = val0
	valueLimbs[1] = val1
	valueLimbs[2] = val2
	valueLimbs[3] = val3
	zero := qm31.Zero()
	for i := 4; i < len(valueLimbs); i++ {
		valueLimbs[i] = zero
	}

	memRes := MemVerifyEvaluate(
		qm31,
		input[0],
		valueLimbs,
		id,
		memoryAddressElements,
		memoryIDElements,
		sum,
		domainVanishInv,
		randomCoeff,
	)
	sum = memRes.Sum

	return VerifyBlakeWordResult{
		Sum:              sum,
		RangeCheckSum:    rangeCheckSum,
		AddressLookupSum: memRes.AddressLookupSum,
		IdToBigLookupSum: memRes.IdToBigLookupSum,
	}
}
