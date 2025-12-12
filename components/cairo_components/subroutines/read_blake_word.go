package subroutines

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

type ReadBlakeWordResult struct {
	Sum              m31.QM31
	RangeCheckSum    m31.QM31
	AddressLookupSum m31.QM31
	IdToBigLookupSum m31.QM31
}

func ReadBlakeWordEvaluate(
	qm31 *m31.QM31Chip,
	address m31.QM31,
	low16 m31.QM31,
	high16 m31.QM31,
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
) ReadBlakeWordResult {
	verifyRes := VerifyBlakeWordEvaluate(
		qm31,
		[3]m31.QM31{address, low16, high16},
		low7MSBits,
		high14MSBits,
		high5MSBits,
		id,
		rangeCheckElements,
		memoryAddressElements,
		memoryIDElements,
		sum,
		domainVanishInv,
		randomCoeff,
	)

	return ReadBlakeWordResult(verifyRes)
}
