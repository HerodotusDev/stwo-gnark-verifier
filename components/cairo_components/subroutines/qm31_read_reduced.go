package subroutines

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

type Qm31ReadReducedResult struct {
	Sum              m31.QM31
	AddressLookupSum m31.QM31
	IdToBigLookupSum m31.QM31
	RangeCheckSum    m31.QM31
	ReducedLimbs     [4]m31.QM31
}

func Qm31ReadReducedEvaluate(
	qm31 *m31.QM31Chip,
	input m31.QM31,
	id m31.QM31,
	limbs []m31.QM31,
	deltaABInv m31.QM31,
	deltaCDInv m31.QM31,
	memoryAddressElements m31.InteractionElements,
	memoryIdToBigElements m31.InteractionElements,
	rangeCheckElements m31.InteractionElements,
	sum m31.QM31,
	domainVanishInv m31.QM31,
	randomCoeff m31.QM31,
) Qm31ReadReducedResult {
	if len(limbs) != 16 {
		panic("Qm31ReadReducedEvaluate expects 16 limbs")
	}

	readResult := ReadPositiveNumBits144Evaluate(
		qm31,
		input,
		id,
		limbs,
		memoryAddressElements,
		memoryIdToBigElements,
		sum,
		domainVanishInv,
		randomCoeff,
	)
	sum = readResult.Sum

	rangeCheckSum, err := qm31.Combine(
		rangeCheckElements,
		[]m31.QM31{limbs[3], limbs[7], limbs[11], limbs[15]},
	)
	if err != nil {
		panic(err)
	}

	total := qm31Const(1548)

	a := qm31.Add(qm31.Add(limbs[0], limbs[1]), qm31.Add(limbs[2], limbs[3]))
	a = qm31.Sub(a, total)
	b := qm31.Add(qm31.Add(limbs[4], limbs[5]), qm31.Add(limbs[6], limbs[7]))
	b = qm31.Sub(b, total)
	c := qm31.Add(qm31.Add(limbs[8], limbs[9]), qm31.Add(limbs[10], limbs[11]))
	c = qm31.Sub(c, total)
	d := qm31.Add(qm31.Add(limbs[12], limbs[13]), qm31.Add(limbs[14], limbs[15]))
	d = qm31.Sub(d, total)

	constraint := qm31.Sub(qm31.Mul(qm31.Mul(a, b), deltaABInv), qm31.One())
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	constraint = qm31.Sub(qm31.Mul(qm31.Mul(c, d), deltaCDInv), qm31.One())
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	base := []m31.QM31{qm31Const(1), qm31Const(512), qm31Const(262144), qm31Const(134217728)}
	var reduced [4]m31.QM31
	for i := 0; i < 4; i++ {
		val := qm31.Zero()
		for j := 0; j < 4; j++ {
			val = qm31.Add(val, qm31.Mul(limbs[i*4+j], base[j]))
		}
		reduced[i] = val
	}

	return Qm31ReadReducedResult{
		Sum:              sum,
		AddressLookupSum: readResult.AddressLookupSum,
		IdToBigLookupSum: readResult.IdToBigLookupSum,
		RangeCheckSum:    rangeCheckSum,
		ReducedLimbs:     reduced,
	}
}
