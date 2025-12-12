package subroutines

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

type LinearCombinationRangeResult struct {
	RangeSum0 m31.QM31
	RangeSum1 m31.QM31
	RangeSum2 m31.QM31
	Sum       m31.QM31
}

func LinearCombinationN1Coefs2Evaluate(
	qm31 *m31.QM31Chip,
	input [10]m31.QM31,
	combination [10]m31.QM31,
	pCoef m31.QM31,
	sum m31.QM31,
	domainVanishInv m31.QM31,
	randomCoeff m31.QM31,
) m31.QM31 {
	expected := computeCombinationTerms(qm31, input[:], []int64{2})
	carries, finalTerm := computeLinearCombinationCarries(
		qm31,
		expected,
		combination[:],
		pCoef,
		qm31Const(16),
		qm31Const(136),
		qm31Const(256),
	)

	constraint := qm31.Mul(finalTerm, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	sum = enforceCubicConstraint(qm31, sum, randomCoeff, domainVanishInv, pCoef)
	for _, carry := range carries {
		sum = enforceCubicConstraint(qm31, sum, randomCoeff, domainVanishInv, carry)
	}

	return sum
}

func LinearCombinationN2Coefs11Evaluate(
	qm31 *m31.QM31Chip,
	input [20]m31.QM31,
	combination [10]m31.QM31,
	pCoef m31.QM31,
	sum m31.QM31,
	domainVanishInv m31.QM31,
	randomCoeff m31.QM31,
) m31.QM31 {
	expected := computeCombinationTerms(qm31, input[:], []int64{1, 1})
	carries, finalTerm := computeLinearCombinationCarries(
		qm31,
		expected,
		combination[:],
		pCoef,
		qm31Const(16),
		qm31Const(136),
		qm31Const(256),
	)

	constraint := qm31.Mul(finalTerm, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	sum = enforceCubicConstraint(qm31, sum, randomCoeff, domainVanishInv, pCoef)
	for _, carry := range carries {
		sum = enforceCubicConstraint(qm31, sum, randomCoeff, domainVanishInv, carry)
	}

	return sum
}

func LinearCombinationN4Coefs3111Evaluate(
	qm31 *m31.QM31Chip,
	input [40]m31.QM31,
	combination [10]m31.QM31,
	pCoef m31.QM31,
	rangeCheckElements m31.InteractionElements,
	sum m31.QM31,
	domainVanishInv m31.QM31,
	randomCoeff m31.QM31,
) LinearCombinationRangeResult {
	expected := computeCombinationTerms(qm31, input[:], []int64{3, 1, 1, 1})
	carries, finalTerm := computeLinearCombinationCarries(
		qm31,
		expected,
		combination[:],
		pCoef,
		qm31Const(16),
		qm31Const(136),
		qm31Const(256),
	)

	constraint := qm31.Mul(finalTerm, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	shift := qm31Const(1)

	rangeValues0 := []m31.QM31{
		qm31.Add(pCoef, shift),
		qm31.Add(carries[0], shift),
		qm31.Add(carries[1], shift),
		qm31.Add(carries[2], shift),
		qm31.Add(carries[3], shift),
	}

	rangeValues1 := []m31.QM31{
		qm31.Add(carries[4], shift),
		qm31.Add(carries[5], shift),
		qm31.Add(carries[6], shift),
		qm31.Add(carries[7], shift),
		qm31.Add(carries[8], shift),
	}

	rangeSum0 := combineRangeValues(qm31, rangeCheckElements, rangeValues0)
	rangeSum1 := combineRangeValues(qm31, rangeCheckElements, rangeValues1)

	return LinearCombinationRangeResult{
		RangeSum0: rangeSum0,
		RangeSum1: rangeSum1,
		Sum:       sum,
	}
}

func LinearCombinationN4Coefs1M11_1Evaluate(
	qm31 *m31.QM31Chip,
	input [40]m31.QM31,
	combination [10]m31.QM31,
	pCoef m31.QM31,
	rangeCheckElements m31.InteractionElements,
	sum m31.QM31,
	domainVanishInv m31.QM31,
	randomCoeff m31.QM31,
) LinearCombinationRangeResult {
	expected := computeCombinationTerms(qm31, input[:], []int64{1, -1, 1, 1})
	carries, finalTerm := computeLinearCombinationCarries(
		qm31,
		expected,
		combination[:],
		pCoef,
		qm31Const(16),
		qm31Const(136),
		qm31Const(256),
	)

	constraint := qm31.Mul(finalTerm, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	shift := qm31Const(2)

	rangeValues0 := []m31.QM31{
		qm31.Add(pCoef, shift),
		qm31.Add(carries[0], shift),
		qm31.Add(carries[1], shift),
		qm31.Add(carries[2], shift),
		qm31.Add(carries[3], shift),
	}

	rangeValues1 := []m31.QM31{
		qm31.Add(carries[4], shift),
		qm31.Add(carries[5], shift),
		qm31.Add(carries[6], shift),
		qm31.Add(carries[7], shift),
		qm31.Add(carries[8], shift),
	}

	rangeSum0 := combineRangeValues(qm31, rangeCheckElements, rangeValues0)
	rangeSum1 := combineRangeValues(qm31, rangeCheckElements, rangeValues1)

	return LinearCombinationRangeResult{
		RangeSum0: rangeSum0,
		RangeSum1: rangeSum1,
		Sum:       sum,
	}
}

func LinearCombinationN4Coefs11M2_1Evaluate(
	qm31 *m31.QM31Chip,
	input [40]m31.QM31,
	combination [10]m31.QM31,
	pCoef m31.QM31,
	rangeCheckElements m31.InteractionElements,
	sum m31.QM31,
	domainVanishInv m31.QM31,
	randomCoeff m31.QM31,
) LinearCombinationRangeResult {
	expected := computeCombinationTerms(qm31, input[:], []int64{1, 1, -2, 1})
	carries, finalTerm := computeLinearCombinationCarries(
		qm31,
		expected,
		combination[:],
		pCoef,
		qm31Const(16),
		qm31Const(136),
		qm31Const(256),
	)

	constraint := qm31.Mul(finalTerm, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	shift := qm31Const(3)

	rangeValues0 := []m31.QM31{
		qm31.Add(pCoef, shift),
		qm31.Add(carries[0], shift),
		qm31.Add(carries[1], shift),
		qm31.Add(carries[2], shift),
		qm31.Add(carries[3], shift),
	}

	rangeValues1 := []m31.QM31{
		qm31.Add(carries[4], shift),
		qm31.Add(carries[5], shift),
		qm31.Add(carries[6], shift),
		qm31.Add(carries[7], shift),
		qm31.Add(carries[8], shift),
	}

	rangeSum0 := combineRangeValues(qm31, rangeCheckElements, rangeValues0)
	rangeSum1 := combineRangeValues(qm31, rangeCheckElements, rangeValues1)

	return LinearCombinationRangeResult{
		RangeSum0: rangeSum0,
		RangeSum1: rangeSum1,
		Sum:       sum,
	}
}

func LinearCombinationN4Coefs42_11Evaluate(
	qm31 *m31.QM31Chip,
	input [40]m31.QM31,
	combination [10]m31.QM31,
	pCoef m31.QM31,
	range4444Elements m31.InteractionElements,
	range44Elements m31.InteractionElements,
	sum m31.QM31,
	domainVanishInv m31.QM31,
	randomCoeff m31.QM31,
) LinearCombinationRangeResult {
	expected := computeCombinationTerms(qm31, input[:], []int64{4, 2, 1, 1})
	carries, finalTerm := computeLinearCombinationCarries(
		qm31,
		expected,
		combination[:],
		pCoef,
		qm31Const(16),
		qm31Const(136),
		qm31Const(256),
	)

	constraint := qm31.Mul(finalTerm, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	shift := qm31Const(1)

	rangeValues0 := []m31.QM31{
		qm31.Add(pCoef, shift),
		qm31.Add(carries[0], shift),
		qm31.Add(carries[1], shift),
		qm31.Add(carries[2], shift),
	}

	rangeValues1 := []m31.QM31{
		qm31.Add(carries[3], shift),
		qm31.Add(carries[4], shift),
		qm31.Add(carries[5], shift),
		qm31.Add(carries[6], shift),
	}

	rangeValues2 := []m31.QM31{
		qm31.Add(carries[7], shift),
		qm31.Add(carries[8], shift),
	}

	rangeSum0 := combineRangeValues(qm31, range4444Elements, rangeValues0)
	rangeSum1 := combineRangeValues(qm31, range4444Elements, rangeValues1)
	rangeSum2 := combineRangeValues(qm31, range44Elements, rangeValues2)

	return LinearCombinationRangeResult{
		RangeSum0: rangeSum0,
		RangeSum1: rangeSum1,
		RangeSum2: rangeSum2,
		Sum:       sum,
	}
}

func LinearCombinationN4Coefs42M2_1Evaluate(
	qm31 *m31.QM31Chip,
	input [40]m31.QM31,
	combination [10]m31.QM31,
	pCoef m31.QM31,
	range4444Elements m31.InteractionElements,
	range44Elements m31.InteractionElements,
	sum m31.QM31,
	domainVanishInv m31.QM31,
	randomCoeff m31.QM31,
) LinearCombinationRangeResult {
	expected := computeCombinationTerms(qm31, input[:], []int64{4, 2, -2, 1})
	carries, finalTerm := computeLinearCombinationCarries(
		qm31,
		expected,
		combination[:],
		pCoef,
		qm31Const(16),
		qm31Const(136),
		qm31Const(256),
	)

	constraint := qm31.Mul(finalTerm, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	shift := qm31Const(3)

	rangeValues0 := []m31.QM31{
		qm31.Add(pCoef, shift),
		qm31.Add(carries[0], shift),
		qm31.Add(carries[1], shift),
		qm31.Add(carries[2], shift),
	}

	rangeValues1 := []m31.QM31{
		qm31.Add(carries[3], shift),
		qm31.Add(carries[4], shift),
		qm31.Add(carries[5], shift),
		qm31.Add(carries[6], shift),
	}

	rangeValues2 := []m31.QM31{
		qm31.Add(carries[7], shift),
		qm31.Add(carries[8], shift),
	}

	rangeSum0 := combineRangeValues(qm31, range4444Elements, rangeValues0)
	rangeSum1 := combineRangeValues(qm31, range4444Elements, rangeValues1)
	rangeSum2 := combineRangeValues(qm31, range44Elements, rangeValues2)

	return LinearCombinationRangeResult{
		RangeSum0: rangeSum0,
		RangeSum1: rangeSum1,
		RangeSum2: rangeSum2,
		Sum:       sum,
	}
}

func LinearCombinationN6Coefs42_3_1M11Evaluate(
	qm31 *m31.QM31Chip,
	input [60]m31.QM31,
	combination [10]m31.QM31,
	pCoef m31.QM31,
	range4444Elements m31.InteractionElements,
	range44Elements m31.InteractionElements,
	sum m31.QM31,
	domainVanishInv m31.QM31,
	randomCoeff m31.QM31,
) LinearCombinationRangeResult {
	expected := computeCombinationTerms(qm31, input[:], []int64{4, 2, 3, 1, -1, 1})
	carries, finalTerm := computeLinearCombinationCarries(
		qm31,
		expected,
		combination[:],
		pCoef,
		qm31Const(16),
		qm31Const(136),
		qm31Const(256),
	)

	constraint := qm31.Mul(finalTerm, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	shift := qm31Const(2)

	rangeValues0 := []m31.QM31{
		qm31.Add(pCoef, shift),
		qm31.Add(carries[0], shift),
		qm31.Add(carries[1], shift),
		qm31.Add(carries[2], shift),
	}

	rangeValues1 := []m31.QM31{
		qm31.Add(carries[3], shift),
		qm31.Add(carries[4], shift),
		qm31.Add(carries[5], shift),
		qm31.Add(carries[6], shift),
	}

	rangeValues2 := []m31.QM31{
		qm31.Add(carries[7], shift),
		qm31.Add(carries[8], shift),
	}

	rangeSum0 := combineRangeValues(qm31, range4444Elements, rangeValues0)
	rangeSum1 := combineRangeValues(qm31, range4444Elements, rangeValues1)
	rangeSum2 := combineRangeValues(qm31, range44Elements, rangeValues2)

	return LinearCombinationRangeResult{
		RangeSum0: rangeSum0,
		RangeSum1: rangeSum1,
		RangeSum2: rangeSum2,
		Sum:       sum,
	}
}

// Helpers

func computeCombinationTerms(qm31 *m31.QM31Chip, inputs []m31.QM31, coeffs []int64) []m31.QM31 {
	stride := len(inputs) / len(coeffs)
	result := make([]m31.QM31, 10)
	for i := 0; i < 10; i++ {
		acc := qm31.Zero()
		for idx, coef := range coeffs {
			term := inputs[i+idx*stride]
			acc = addWithCoeff(qm31, acc, term, coef)
		}
		result[i] = acc
	}
	return result
}

func computeLinearCombinationCarries(
	qm31 *m31.QM31Chip,
	expected []m31.QM31,
	combination []m31.QM31,
	pCoef m31.QM31,
	scale m31.QM31,
	scale136 m31.QM31,
	scale256 m31.QM31,
) ([]m31.QM31, m31.QM31) {
	carries := make([]m31.QM31, 9)

	tmp := qm31.Sub(expected[0], combination[0])
	tmp = qm31.Sub(tmp, pCoef)
	carry := qm31.Mul(tmp, scale)
	carries[0] = carry

	for i := 1; i <= 6; i++ {
		tmp = qm31.Add(carry, expected[i])
		tmp = qm31.Sub(tmp, combination[i])
		carry = qm31.Mul(tmp, scale)
		carries[i] = carry
	}

	tmp = qm31.Add(carry, expected[7])
	tmp = qm31.Sub(tmp, qm31.Mul(pCoef, scale136))
	tmp = qm31.Sub(tmp, combination[7])
	carry = qm31.Mul(tmp, scale)
	carries[7] = carry

	tmp = qm31.Add(carry, expected[8])
	tmp = qm31.Sub(tmp, combination[8])
	carry = qm31.Mul(tmp, scale)
	carries[8] = carry

	final := qm31.Add(carry, expected[9])
	final = qm31.Sub(final, combination[9])
	final = qm31.Sub(final, qm31.Mul(pCoef, scale256))

	return carries, final
}

func addWithCoeff(
	qm31 *m31.QM31Chip,
	acc m31.QM31,
	value m31.QM31,
	coef int64,
) m31.QM31 {
	switch coef {
	case 1:
		return qm31.Add(acc, value)
	case -1:
		return qm31.Sub(acc, value)
	default:
		if coef > 0 {
			return qm31.Add(acc, qm31.Mul(qm31Const(uint64(coef)), value))
		}
		return qm31.Sub(acc, qm31.Mul(qm31Const(uint64(-coef)), value))
	}
}

func combineRangeValues(
	qm31 *m31.QM31Chip,
	elements m31.InteractionElements,
	values []m31.QM31,
) m31.QM31 {
	if len(values) == 0 {
		return qm31.Zero()
	}
	result, err := qm31.Combine(elements, values)
	if err != nil {
		panic(err)
	}
	return result
}
