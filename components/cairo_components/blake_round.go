package cairo_components

import (
	sub "github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components/subroutines"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
)

const (
	BlakeRoundTraceColumns       = 212
	BlakeRoundInteractionColumns = 120
)

type BlakeRoundClaim struct {
	LogSize frontend.Variable
}

type BlakeRoundInteractionClaim struct {
	ClaimedSum m31.QM31
}

type BlakeRoundComponent struct {
	qm31 *m31.QM31Chip

	blakeRoundSigmaElements m31.InteractionElements
	rangeCheck725Elements   m31.InteractionElements
	memoryAddressToId       m31.InteractionElements
	memoryIdToBig           m31.InteractionElements
	blakeGElements          m31.InteractionElements
	blakeRoundElements      m31.InteractionElements

	claimedSum    m31.QM31
	columnSizeInv m31.QM31
	vanishEvalInv m31.QM31
	logSize       frontend.Variable
}

func NewBlakeRound(
	api frontend.API,
	qm31 *m31.QM31Chip,
	blakeRoundSigma m31.InteractionElements,
	rangeCheck725 m31.InteractionElements,
	memoryAddressToId m31.InteractionElements,
	memoryIdToBig m31.InteractionElements,
	blakeG m31.InteractionElements,
	blakeRound m31.InteractionElements,
	vanishEvalInv m31.QM31,
	claim BlakeRoundClaim,
	interactionClaim BlakeRoundInteractionClaim,
) BlakeRoundComponent {
	columnSize := computeColumnSize(api, claim.LogSize)
	columnSizeInv := qm31.Inverse(columnSize)

	return BlakeRoundComponent{
		qm31:                    qm31,
		blakeRoundSigmaElements: blakeRoundSigma,
		rangeCheck725Elements:   rangeCheck725,
		memoryAddressToId:       memoryAddressToId,
		memoryIdToBig:           memoryIdToBig,
		blakeGElements:          blakeG,
		blakeRoundElements:      blakeRound,
		claimedSum:              interactionClaim.ClaimedSum,
		columnSizeInv:           columnSizeInv,
		vanishEvalInv:           vanishEvalInv,
		logSize:                 claim.LogSize,
	}
}

func (c BlakeRoundComponent) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	traceSampledValues, interactionSampledValues := traces.Take(BlakeRoundTraceColumns, BlakeRoundInteractionColumns)

	// ╔══════════════════════════════════╗
	// ║        Preprocessed Trace        ║
	// ╚══════════════════════════════════╝
	// (none)

	// ╔══════════════════════════════════╗
	// ║            Main Trace            ║
	// ╚══════════════════════════════════╝
	// Main Trace helpers
	getTrace := func(idx int) m31.QM31 {
		col := traceSampledValues[idx]
		if len(col) == 0 {
			panic("trace column empty")
		}
		return col[0]
	}

	type messageWord struct {
		low16  m31.QM31
		high16 m31.QM31
		low7   m31.QM31
		high14 m31.QM31
		high5  m31.QM31
		id     m31.QM31
	}

	qm31 := c.qm31
	domainInv := c.vanishEvalInv

	inputLimb := make([]m31.QM31, 35)
	for i := 0; i < 35; i++ {
		inputLimb[i] = getTrace(i)
	}

	sigmaOutputs := make([]m31.QM31, 16)
	for i := 0; i < 16; i++ {
		sigmaOutputs[i] = getTrace(35 + i)
	}

	messageWords := make([]messageWord, 16)
	base := 51
	for i := 0; i < 16; i++ {
		messageWords[i] = messageWord{
			low16:  getTrace(base),
			high16: getTrace(base + 1),
			low7:   getTrace(base + 2),
			high14: getTrace(base + 3),
			high5:  getTrace(base + 4),
			id:     getTrace(base + 5),
		}
		base += 6
	}

	blakeGOutputs := make([][8]m31.QM31, 8)
	for group := 0; group < 8; group++ {
		groupBase := 147 + group*8
		for limb := 0; limb < 8; limb++ {
			blakeGOutputs[group][limb] = getTrace(groupBase + limb)
		}
	}

	enabler := getTrace(211)

	// ╔══════════════════════════════════╗
	// ║         Interaction Trace        ║
	// ╚══════════════════════════════════╝
	// Use InteractionTrace.Partial to build current/previous partials.
	partials := make([]m31.QM31, 30)
	for i := 0; i < 29; i++ {
		partials[i] = interactionSampledValues.Partial(c.qm31, i*4, 0)
	}
	// Last block (start=116) has previous/current samples.
	partials[29] = interactionSampledValues.Partial(c.qm31, 116, 1)
	prevPartial := interactionSampledValues.Partial(c.qm31, 116, 0)

	// Constraint Evaluations
	accumulate := func(constraint m31.QM31) {
		sum = qm31.Add(qm31.Mul(sum, randomCoeff), qm31.Mul(constraint, domainInv))
	}

	// Enforce enabler to be boolean.
	{
		term := qm31.Sub(qm31.Mul(enabler, enabler), enabler)
		accumulate(term)
	}

	// Blake round sigma lookup combination.
	{
		var (
			err             error
			combined        m31.QM31
			blakeRoundSum57 m31.QM31
			blakeRoundSum58 m31.QM31
		)

		values := make([]m31.QM31, 17)
		values[0] = inputLimb[1]
		copy(values[1:], sigmaOutputs)
		combined, err = qm31.Combine(c.blakeRoundSigmaElements, values)
		if err != nil {
			panic(err)
		}
		blakeRoundSigmaSum := combined

		rangeSums := make([]m31.QM31, 16)
		addressSums := make([]m31.QM31, 16)
		idSums := make([]m31.QM31, 16)

		for i := 0; i < 16; i++ {
			address := qm31.Add(inputLimb[34], sigmaOutputs[i])
			word := messageWords[i]
			res := sub.ReadBlakeWordEvaluate(
				qm31,
				address,
				word.low16,
				word.high16,
				word.low7,
				word.high14,
				word.high5,
				word.id,
				c.rangeCheck725Elements,
				c.memoryAddressToId,
				c.memoryIdToBig,
				sum,
				domainInv,
				randomCoeff,
			)
			sum = res.Sum
			rangeSums[i] = res.RangeCheckSum
			addressSums[i] = res.AddressLookupSum
			idSums[i] = res.IdToBigLookupSum
		}

		blakeG := func(group, limb int) m31.QM31 {
			return blakeGOutputs[group][limb]
		}

		buildValues := func(values ...m31.QM31) []m31.QM31 {
			result := make([]m31.QM31, len(values))
			copy(result, values)
			return result
		}

		blakeGSums := make([]m31.QM31, 8)

		blakeGSums[0], err = qm31.Combine(
			c.blakeGElements,
			buildValues(
				inputLimb[2], inputLimb[3], inputLimb[10], inputLimb[11],
				inputLimb[18], inputLimb[19], inputLimb[26], inputLimb[27],
				messageWords[0].low16, messageWords[0].high16,
				messageWords[1].low16, messageWords[1].high16,
				blakeG(0, 0), blakeG(0, 1), blakeG(0, 2), blakeG(0, 3),
				blakeG(0, 4), blakeG(0, 5), blakeG(0, 6), blakeG(0, 7),
			),
		)
		if err != nil {
			panic(err)
		}

		blakeGSums[1], err = qm31.Combine(
			c.blakeGElements,
			buildValues(
				inputLimb[4], inputLimb[5], inputLimb[12], inputLimb[13],
				inputLimb[20], inputLimb[21], inputLimb[28], inputLimb[29],
				messageWords[2].low16, messageWords[2].high16,
				messageWords[3].low16, messageWords[3].high16,
				blakeG(1, 0), blakeG(1, 1), blakeG(1, 2), blakeG(1, 3),
				blakeG(1, 4), blakeG(1, 5), blakeG(1, 6), blakeG(1, 7),
			),
		)
		if err != nil {
			panic(err)
		}

		blakeGSums[2], err = qm31.Combine(
			c.blakeGElements,
			buildValues(
				inputLimb[6], inputLimb[7], inputLimb[14], inputLimb[15],
				inputLimb[22], inputLimb[23], inputLimb[30], inputLimb[31],
				messageWords[4].low16, messageWords[4].high16,
				messageWords[5].low16, messageWords[5].high16,
				blakeG(2, 0), blakeG(2, 1), blakeG(2, 2), blakeG(2, 3),
				blakeG(2, 4), blakeG(2, 5), blakeG(2, 6), blakeG(2, 7),
			),
		)
		if err != nil {
			panic(err)
		}

		blakeGSums[3], err = qm31.Combine(
			c.blakeGElements,
			buildValues(
				inputLimb[8], inputLimb[9], inputLimb[16], inputLimb[17],
				inputLimb[24], inputLimb[25], inputLimb[32], inputLimb[33],
				messageWords[6].low16, messageWords[6].high16,
				messageWords[7].low16, messageWords[7].high16,
				blakeG(3, 0), blakeG(3, 1), blakeG(3, 2), blakeG(3, 3),
				blakeG(3, 4), blakeG(3, 5), blakeG(3, 6), blakeG(3, 7),
			),
		)
		if err != nil {
			panic(err)
		}

		blakeGSums[4], err = qm31.Combine(
			c.blakeGElements,
			buildValues(
				blakeG(0, 0), blakeG(0, 1), blakeG(1, 2), blakeG(1, 3),
				blakeG(2, 4), blakeG(2, 5), blakeG(3, 6), blakeG(3, 7),
				messageWords[8].low16, messageWords[8].high16,
				messageWords[9].low16, messageWords[9].high16,
				blakeG(4, 0), blakeG(4, 1), blakeG(4, 2), blakeG(4, 3),
				blakeG(4, 4), blakeG(4, 5), blakeG(4, 6), blakeG(4, 7),
			),
		)
		if err != nil {
			panic(err)
		}

		blakeGSums[5], err = qm31.Combine(
			c.blakeGElements,
			buildValues(
				blakeG(1, 0), blakeG(1, 1), blakeG(2, 2), blakeG(2, 3),
				blakeG(3, 4), blakeG(3, 5), blakeG(0, 6), blakeG(0, 7),
				messageWords[10].low16, messageWords[10].high16,
				messageWords[11].low16, messageWords[11].high16,
				blakeG(5, 0), blakeG(5, 1), blakeG(5, 2), blakeG(5, 3),
				blakeG(5, 4), blakeG(5, 5), blakeG(5, 6), blakeG(5, 7),
			),
		)
		if err != nil {
			panic(err)
		}

		blakeGSums[6], err = qm31.Combine(
			c.blakeGElements,
			buildValues(
				blakeG(2, 0), blakeG(2, 1), blakeG(3, 2), blakeG(3, 3),
				blakeG(0, 4), blakeG(0, 5), blakeG(1, 6), blakeG(1, 7),
				messageWords[12].low16, messageWords[12].high16,
				messageWords[13].low16, messageWords[13].high16,
				blakeG(6, 0), blakeG(6, 1), blakeG(6, 2), blakeG(6, 3),
				blakeG(6, 4), blakeG(6, 5), blakeG(6, 6), blakeG(6, 7),
			),
		)
		if err != nil {
			panic(err)
		}

		blakeGSums[7], err = qm31.Combine(
			c.blakeGElements,
			buildValues(
				blakeG(3, 0), blakeG(3, 1), blakeG(0, 2), blakeG(0, 3),
				blakeG(1, 4), blakeG(1, 5), blakeG(2, 6), blakeG(2, 7),
				messageWords[14].low16, messageWords[14].high16,
				messageWords[15].low16, messageWords[15].high16,
				blakeG(7, 0), blakeG(7, 1), blakeG(7, 2), blakeG(7, 3),
				blakeG(7, 4), blakeG(7, 5), blakeG(7, 6), blakeG(7, 7),
			),
		)
		if err != nil {
			panic(err)
		}

		blakeRoundSum57, err = qm31.Combine(
			c.blakeRoundElements,
			buildValues(
				inputLimb[0], inputLimb[1], inputLimb[2], inputLimb[3],
				inputLimb[4], inputLimb[5], inputLimb[6], inputLimb[7],
				inputLimb[8], inputLimb[9], inputLimb[10], inputLimb[11],
				inputLimb[12], inputLimb[13], inputLimb[14], inputLimb[15],
				inputLimb[16], inputLimb[17], inputLimb[18], inputLimb[19],
				inputLimb[20], inputLimb[21], inputLimb[22], inputLimb[23],
				inputLimb[24], inputLimb[25], inputLimb[26], inputLimb[27],
				inputLimb[28], inputLimb[29], inputLimb[30], inputLimb[31],
				inputLimb[32], inputLimb[33], inputLimb[34],
			),
		)
		if err != nil {
			panic(err)
		}

		blakeRoundSum58, err = qm31.Combine(
			c.blakeRoundElements,
			buildValues(
				inputLimb[0], qm31.Add(inputLimb[1], qm31Const(1)),
				blakeG(4, 0), blakeG(4, 1),
				blakeG(5, 0), blakeG(5, 1),
				blakeG(6, 0), blakeG(6, 1),
				blakeG(7, 0), blakeG(7, 1),
				blakeG(7, 2), blakeG(7, 3),
				blakeG(4, 2), blakeG(4, 3),
				blakeG(5, 2), blakeG(5, 3),
				blakeG(6, 2), blakeG(6, 3),
				blakeG(6, 4), blakeG(6, 5),
				blakeG(7, 4), blakeG(7, 5),
				blakeG(4, 4), blakeG(4, 5),
				blakeG(5, 4), blakeG(5, 5),
				blakeG(5, 6), blakeG(5, 7),
				blakeG(6, 6), blakeG(6, 7),
				blakeG(7, 6), blakeG(7, 7),
				blakeG(4, 6), blakeG(4, 7),
				inputLimb[34],
			),
		)
		if err != nil {
			panic(err)
		}

		rangeSumByNumber := func(num int) m31.QM31 {
			if num%3 != 1 {
				panic("invalid range sum number")
			}
			index := (num - 1) / 3
			if index < 0 || index >= len(rangeSums) {
				panic("range sum index out of bounds")
			}
			return rangeSums[index]
		}

		addressSumByNumber := func(num int) m31.QM31 {
			if num%3 != 2 {
				panic("invalid address sum number")
			}
			index := (num - 2) / 3
			if index < 0 || index >= len(addressSums) {
				panic("address sum index out of bounds")
			}
			return addressSums[index]
		}

		idSumByNumber := func(num int) m31.QM31 {
			if num%3 != 0 {
				panic("invalid id sum number")
			}
			index := (num - 3) / 3
			if index < 0 || index >= len(idSums) {
				panic("id sum index out of bounds")
			}
			return idSums[index]
		}

		addDiffConstraint := func(currIdx int, sumA, sumB m31.QM31) {
			diff := qm31.Sub(partials[currIdx], partials[currIdx-1])
			term := qm31.Mul(diff, sumA)
			term = qm31.Mul(term, sumB)
			term = qm31.Sub(term, sumA)
			term = qm31.Sub(term, sumB)
			accumulate(term)
		}

		// g0
		{
			term := qm31.Mul(partials[0], blakeRoundSigmaSum)
			rangeSum := rangeSumByNumber(1)
			term = qm31.Mul(term, rangeSum)
			term = qm31.Sub(term, blakeRoundSigmaSum)
			term = qm31.Sub(term, rangeSum)
			accumulate(term)
		}

		addDiffConstraint(1, addressSumByNumber(2), idSumByNumber(3))
		addDiffConstraint(2, rangeSumByNumber(4), addressSumByNumber(5))
		addDiffConstraint(3, idSumByNumber(6), rangeSumByNumber(7))
		addDiffConstraint(4, addressSumByNumber(8), idSumByNumber(9))
		addDiffConstraint(5, rangeSumByNumber(10), addressSumByNumber(11))
		addDiffConstraint(6, idSumByNumber(12), rangeSumByNumber(13))
		addDiffConstraint(7, addressSumByNumber(14), idSumByNumber(15))
		addDiffConstraint(8, rangeSumByNumber(16), addressSumByNumber(17))
		addDiffConstraint(9, idSumByNumber(18), rangeSumByNumber(19))
		addDiffConstraint(10, addressSumByNumber(20), idSumByNumber(21))
		addDiffConstraint(11, rangeSumByNumber(22), addressSumByNumber(23))
		addDiffConstraint(12, idSumByNumber(24), rangeSumByNumber(25))
		addDiffConstraint(13, addressSumByNumber(26), idSumByNumber(27))
		addDiffConstraint(14, rangeSumByNumber(28), addressSumByNumber(29))
		addDiffConstraint(15, idSumByNumber(30), rangeSumByNumber(31))
		addDiffConstraint(16, addressSumByNumber(32), idSumByNumber(33))
		addDiffConstraint(17, rangeSumByNumber(34), addressSumByNumber(35))
		addDiffConstraint(18, idSumByNumber(36), rangeSumByNumber(37))
		addDiffConstraint(19, addressSumByNumber(38), idSumByNumber(39))
		addDiffConstraint(20, rangeSumByNumber(40), addressSumByNumber(41))
		addDiffConstraint(21, idSumByNumber(42), rangeSumByNumber(43))
		addDiffConstraint(22, addressSumByNumber(44), idSumByNumber(45))
		addDiffConstraint(23, rangeSumByNumber(46), addressSumByNumber(47))

		addDiffConstraint(24, idSumByNumber(48), blakeGSums[0])

		addDiffConstraint(25, blakeGSums[1], blakeGSums[2])
		addDiffConstraint(26, blakeGSums[3], blakeGSums[4])
		addDiffConstraint(27, blakeGSums[5], blakeGSums[6])

		// g28 with enabler adjustment.
		{
			diff := qm31.Sub(partials[28], partials[27])
			term := qm31.Mul(diff, blakeGSums[7])
			term = qm31.Mul(term, blakeRoundSum57)
			term = qm31.Sub(term, qm31.Mul(blakeGSums[7], enabler))
			term = qm31.Sub(term, blakeRoundSum57)
			accumulate(term)
		}

		// Final constraint.
		{
			diff := qm31.Sub(partials[29], partials[28])
			diff = qm31.Sub(diff, prevPartial)
			diff = qm31.Add(diff, qm31.Mul(c.claimedSum, c.columnSizeInv))
			term := qm31.Mul(diff, blakeRoundSum58)
			term = qm31.Add(term, enabler)
			accumulate(term)
		}
	}

	return sum
}
