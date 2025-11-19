package subroutines

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

func BitwiseXorNumBits12Evaluate(
	qm31 *m31.QM31Chip,
	a m31.QM31,
	b m31.QM31,
	xor m31.QM31,
	elements m31.InteractionElements,
) m31.QM31 {
	res, err := qm31.Combine(elements, []m31.QM31{a, b, xor})
	if err != nil {
		panic(err)
	}
	return res
}

func BitwiseXorNumBits8Evaluate(
	qm31 *m31.QM31Chip,
	a m31.QM31,
	b m31.QM31,
	xor m31.QM31,
	elements m31.InteractionElements,
) m31.QM31 {
	res, err := qm31.Combine(elements, []m31.QM31{a, b, xor})
	if err != nil {
		panic(err)
	}
	return res
}

func BitwiseXorNumBits7Evaluate(
	qm31 *m31.QM31Chip,
	a m31.QM31,
	b m31.QM31,
	xor m31.QM31,
	elements m31.InteractionElements,
) m31.QM31 {
	res, err := qm31.Combine(elements, []m31.QM31{a, b, xor})
	if err != nil {
		panic(err)
	}
	return res
}

func BitwiseXorNumBits9Evaluate(
	qm31 *m31.QM31Chip,
	a m31.QM31,
	b m31.QM31,
	xor m31.QM31,
	elements m31.InteractionElements,
) m31.QM31 {
	res, err := qm31.Combine(elements, []m31.QM31{a, b, xor})
	if err != nil {
		panic(err)
	}
	return res
}

func BitwiseXorNumBits4Evaluate(
	qm31 *m31.QM31Chip,
	a m31.QM31,
	b m31.QM31,
	xor m31.QM31,
	elements m31.InteractionElements,
) m31.QM31 {
	res, err := qm31.Combine(elements, []m31.QM31{a, b, xor})
	if err != nil {
		panic(err)
	}
	return res
}
