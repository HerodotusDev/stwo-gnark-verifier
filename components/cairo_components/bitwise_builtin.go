package cairo_components

import (
	sub "github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components/subroutines"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
)

type BitwiseBuiltinClaim struct {
	LogSize                    uint32
	BitwiseBuiltinSegmentStart uint32
}

type BitwiseBuiltinInteractionClaim struct {
	ClaimedSum m31.QM31
}

type BitwiseBuiltinComponent struct {
	qm31 *m31.QM31Chip

	logSize uint8

	memoryAddressToIdElements m31.InteractionElements
	memoryIdToBigElements     m31.InteractionElements
	verifyBitwiseXorElements  m31.InteractionElements

	segmentStart  m31.QM31
	claimedSum    m31.QM31
	columnSizeInv m31.QM31
	vanishEvalInv m31.QM31
}

func NewBitwiseBuiltin(
	qm31 *m31.QM31Chip,
	memoryAddressElements m31.InteractionElements,
	memoryIdToBigElements m31.InteractionElements,
	verifyBitwiseXorElements m31.InteractionElements,
	claim BitwiseBuiltinClaim,
	interactionClaim BitwiseBuiltinInteractionClaim,
) *BitwiseBuiltinComponent {
	if claim.LogSize > 255 {
		panic("bitwise_builtin log size must fit in uint8")
	}

	columnSize := uint64(1) << claim.LogSize
	columnSizeQM := m31.NewQM31FromM31(m31.NewM31Unchecked(columnSize))

	return &BitwiseBuiltinComponent{
		qm31:                      qm31,
		logSize:                   uint8(claim.LogSize),
		memoryAddressToIdElements: memoryAddressElements,
		memoryIdToBigElements:     memoryIdToBigElements,
		verifyBitwiseXorElements:  verifyBitwiseXorElements,
		segmentStart: m31.NewQM31FromM31(
			m31.NewM31Unchecked(uint64(claim.BitwiseBuiltinSegmentStart)),
		),
		claimedSum:    interactionClaim.ClaimedSum,
		columnSizeInv: qm31.Inverse(columnSizeQM),
		vanishEvalInv: qm31.One(),
	}
}

func (c *BitwiseBuiltinComponent) Evaluate(
	sum m31.QM31,
	preprocessedSampledValues PreprocessedSampledValues,
	traceSampledValues [][]m31.QM31,
	interactionSampledValues [][]m31.QM31,
	randomCoeff m31.QM31,
) m31.QM31 {
	if len(traceSampledValues) != 89 {
		panic("bitwise_builtin expects 89 trace columns")
	}
	if len(interactionSampledValues) != 76 {
		panic("bitwise_builtin expects 76 interaction columns")
	}

	getTrace := func(index int) m31.QM31 {
		column := traceSampledValues[index]
		if len(column) == 0 {
			panic("missing trace sample")
		}
		return column[0]
	}
	gatherLimbs := func(start, count int) []m31.QM31 {
		limbs := make([]m31.QM31, count)
		for i := 0; i < count; i++ {
			limbs[i] = getTrace(start + i)
		}
		return limbs
	}

	seq := preprocessedSampledValues.Get(sequencePreprocessedColumn(c.logSize))
	base := c.qm31.Add(c.segmentStart, c.qm31.Mul(seq, qm31Const(5)))

	op0ID := getTrace(0)
	op0Limbs := gatherLimbs(1, 28)
	op1ID := getTrace(29)
	op1Limbs := gatherLimbs(30, 28)
	xorLimbs := gatherLimbs(58, 28)
	andID := getTrace(86)
	xorID := getTrace(87)
	orID := getTrace(88)

	op0Lookup := sub.ReadPositiveNumBits252Evaluate(
		c.qm31,
		base,
		op0ID,
		op0Limbs,
		c.memoryAddressToIdElements,
		c.memoryIdToBigElements,
	)

	op1Address := c.qm31.Add(base, c.qm31.One())
	op1Lookup := sub.ReadPositiveNumBits252Evaluate(
		c.qm31,
		op1Address,
		op1ID,
		op1Limbs,
		c.memoryAddressToIdElements,
		c.memoryIdToBigElements,
	)

	bitwiseSums := make([]m31.QM31, 28)
	andLimbs := make([]m31.QM31, 28)
	orLimbs := make([]m31.QM31, 28)
	andScale := qm31Const(1 << 30)

	for i := 0; i < 28; i++ {
		op0 := op0Limbs[i]
		op1 := op1Limbs[i]
		xorVal := xorLimbs[i]

		bitwiseSums[i] = sub.BitwiseXorNumBits9Evaluate(
			c.qm31,
			op0,
			op1,
			xorVal,
			c.verifyBitwiseXorElements,
		)

		sumOperands := c.qm31.Add(op0, op1)
		andLimbs[i] = c.qm31.Mul(andScale, c.qm31.Sub(sumOperands, xorVal))
		orLimbs[i] = c.qm31.Add(andLimbs[i], xorVal)
	}

	andAddress := c.qm31.Add(base, qm31Const(2))
	andRes := sub.MemVerifyEvaluate(
		c.qm31,
		andAddress,
		andLimbs,
		andID,
		c.memoryAddressToIdElements,
		c.memoryIdToBigElements,
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)
	sum = andRes.Sum

	xorAddress := c.qm31.Add(base, qm31Const(3))
	xorRes := sub.MemVerifyEvaluate(
		c.qm31,
		xorAddress,
		xorLimbs,
		xorID,
		c.memoryAddressToIdElements,
		c.memoryIdToBigElements,
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)
	sum = xorRes.Sum

	orAddress := c.qm31.Add(base, qm31Const(4))
	orRes := sub.MemVerifyEvaluate(
		c.qm31,
		orAddress,
		orLimbs,
		orID,
		c.memoryAddressToIdElements,
		c.memoryIdToBigElements,
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)
	sum = orRes.Sum

	lookups := bitwiseBuiltinLookups{
		memoryAddressToId: []m31.QM31{
			op0Lookup.AddressLookupSum,
			op1Lookup.AddressLookupSum,
			andRes.AddressLookupSum,
			xorRes.AddressLookupSum,
			orRes.AddressLookupSum,
		},
		memoryIdToBig: []m31.QM31{
			op0Lookup.IdToBigLookupSum,
			op1Lookup.IdToBigLookupSum,
			andRes.IdToBigLookupSum,
			xorRes.IdToBigLookupSum,
			orRes.IdToBigLookupSum,
		},
		bitwiseSums: bitwiseSums,
	}

	return c.applyLookupConstraints(sum, interactionSampledValues, randomCoeff, lookups)
}

type bitwiseBuiltinLookups struct {
	memoryAddressToId []m31.QM31
	memoryIdToBig     []m31.QM31
	bitwiseSums       []m31.QM31
}

func (c *BitwiseBuiltinComponent) applyLookupConstraints(
	sum m31.QM31,
	interactionSampledValues [][]m31.QM31,
	randomCoeff m31.QM31,
	lookups bitwiseBuiltinLookups,
) m31.QM31 {
	if len(lookups.memoryAddressToId) != 5 || len(lookups.memoryIdToBig) != 5 {
		panic("bitwise builtin lookup slices must have length 5")
	}
	if len(lookups.bitwiseSums) != 28 {
		panic("bitwise builtin expects 28 bitwise lookup sums")
	}

	partials := make([]m31.QM31, 19)
	index := 0
	for i := 0; i < 18; i++ {
		partials[i] = c.qm31.FromPartialEvals(
			interactionSampledValues[index][0],
			interactionSampledValues[index+1][0],
			interactionSampledValues[index+2][0],
			interactionSampledValues[index+3][0],
		)
		index += 4
	}

	lastColumns := interactionSampledValues[index:]
	if len(lastColumns) != 4 {
		panic("bitwise builtin expected 4 interaction columns for the final partials")
	}
	for _, column := range lastColumns {
		if len(column) < 2 {
			panic("bitwise builtin final interaction columns require two evaluations")
		}
	}

	partials[18] = c.qm31.FromPartialEvals(
		lastColumns[0][1],
		lastColumns[1][1],
		lastColumns[2][1],
		lastColumns[3][1],
	)
	negPartial := c.qm31.FromPartialEvals(
		lastColumns[0][0],
		lastColumns[1][0],
		lastColumns[2][0],
		lastColumns[3][0],
	)

	accumulate := func(delta, lookupA, lookupB m31.QM31) {
		constraint := c.qm31.Mul(delta, c.qm31.Mul(lookupA, lookupB))
		constraint = c.qm31.Sub(constraint, lookupA)
		constraint = c.qm31.Sub(constraint, lookupB)
		constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
		sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)
	}

	accumulate(partials[0], lookups.memoryAddressToId[0], lookups.memoryIdToBig[0])

	diff := c.qm31.Sub(partials[1], partials[0])
	accumulate(diff, lookups.memoryAddressToId[1], lookups.memoryIdToBig[1])

	for i := 0; i < 14; i++ {
		delta := c.qm31.Sub(partials[i+2], partials[i+1])
		accumulate(delta, lookups.bitwiseSums[2*i], lookups.bitwiseSums[2*i+1])
	}

	deltaAnd := c.qm31.Sub(partials[16], partials[15])
	accumulate(deltaAnd, lookups.memoryAddressToId[2], lookups.memoryIdToBig[2])

	deltaXor := c.qm31.Sub(partials[17], partials[16])
	accumulate(deltaXor, lookups.memoryAddressToId[3], lookups.memoryIdToBig[3])

	lastDelta := c.qm31.Sub(partials[18], partials[17])
	lastDelta = c.qm31.Sub(lastDelta, negPartial)
	lastDelta = c.qm31.Add(lastDelta, c.qm31.Mul(c.claimedSum, c.columnSizeInv))
	accumulate(lastDelta, lookups.memoryAddressToId[4], lookups.memoryIdToBig[4])

	return sum
}
