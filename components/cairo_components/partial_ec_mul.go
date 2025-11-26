package cairo_components

import (
	sub "github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components/subroutines"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

const (
	partialEcMulTraceColumns       = 472
	partialEcMulInteractionColumns = 428
	partialEcMulGroupCount         = partialEcMulInteractionColumns / 4
)

type constraintMode uint8

const (
	modePedersen constraintMode = iota
	modeRange9Pair
	modeRange9Range19
	modeRange19Pair
	modeRange19Range9
	modePartial211
	modePartial212
)

type constraintSpec struct {
	Mode   constraintMode
	Curr   int
	Prev   int
	Sum9A  int
	Sum9B  int
	Sum19A int
	Sum19B int
}

var constraintSpecs = []constraintSpec{
	{Mode: modePedersen, Curr: 0, Prev: -1, Sum9A: 1, Sum9B: -1, Sum19A: -1, Sum19B: -1},
	{Mode: modeRange9Pair, Curr: 1, Prev: 0, Sum9A: 2, Sum9B: 3, Sum19A: -1, Sum19B: -1},
	{Mode: modeRange9Pair, Curr: 2, Prev: 1, Sum9A: 4, Sum9B: 5, Sum19A: -1, Sum19B: -1},
	{Mode: modeRange9Pair, Curr: 3, Prev: 2, Sum9A: 6, Sum9B: 7, Sum19A: -1, Sum19B: -1},
	{Mode: modeRange9Pair, Curr: 4, Prev: 3, Sum9A: 8, Sum9B: 9, Sum19A: -1, Sum19B: -1},
	{Mode: modeRange9Pair, Curr: 5, Prev: 4, Sum9A: 10, Sum9B: 11, Sum19A: -1, Sum19B: -1},
	{Mode: modeRange9Pair, Curr: 6, Prev: 5, Sum9A: 12, Sum9B: 13, Sum19A: -1, Sum19B: -1},
	{Mode: modeRange9Pair, Curr: 7, Prev: 6, Sum9A: 14, Sum9B: 15, Sum19A: -1, Sum19B: -1},
	{Mode: modeRange9Pair, Curr: 8, Prev: 7, Sum9A: 16, Sum9B: 17, Sum19A: -1, Sum19B: -1},
	{Mode: modeRange9Pair, Curr: 9, Prev: 8, Sum9A: 18, Sum9B: 19, Sum19A: -1, Sum19B: -1},
	{Mode: modeRange9Pair, Curr: 10, Prev: 9, Sum9A: 20, Sum9B: 21, Sum19A: -1, Sum19B: -1},
	{Mode: modeRange9Pair, Curr: 11, Prev: 10, Sum9A: 22, Sum9B: 23, Sum19A: -1, Sum19B: -1},
	{Mode: modeRange9Pair, Curr: 12, Prev: 11, Sum9A: 24, Sum9B: 25, Sum19A: -1, Sum19B: -1},
	{Mode: modeRange9Pair, Curr: 13, Prev: 12, Sum9A: 26, Sum9B: 27, Sum19A: -1, Sum19B: -1},
	{Mode: modeRange9Pair, Curr: 14, Prev: 13, Sum9A: 28, Sum9B: 29, Sum19A: -1, Sum19B: -1},
	{Mode: modeRange9Pair, Curr: 15, Prev: 14, Sum9A: 30, Sum9B: 31, Sum19A: -1, Sum19B: -1},
	{Mode: modeRange9Pair, Curr: 16, Prev: 15, Sum9A: 32, Sum9B: 33, Sum19A: -1, Sum19B: -1},
	{Mode: modeRange9Pair, Curr: 17, Prev: 16, Sum9A: 34, Sum9B: 35, Sum19A: -1, Sum19B: -1},
	{Mode: modeRange9Pair, Curr: 18, Prev: 17, Sum9A: 36, Sum9B: 37, Sum19A: -1, Sum19B: -1},
	{Mode: modeRange9Pair, Curr: 19, Prev: 18, Sum9A: 38, Sum9B: 39, Sum19A: -1, Sum19B: -1},
	{Mode: modeRange9Pair, Curr: 20, Prev: 19, Sum9A: 40, Sum9B: 41, Sum19A: -1, Sum19B: -1},
	{Mode: modeRange9Pair, Curr: 21, Prev: 20, Sum9A: 42, Sum9B: 43, Sum19A: -1, Sum19B: -1},
	{Mode: modeRange9Pair, Curr: 22, Prev: 21, Sum9A: 44, Sum9B: 45, Sum19A: -1, Sum19B: -1},
	{Mode: modeRange9Pair, Curr: 23, Prev: 22, Sum9A: 46, Sum9B: 47, Sum19A: -1, Sum19B: -1},
	{Mode: modeRange9Pair, Curr: 24, Prev: 23, Sum9A: 48, Sum9B: 49, Sum19A: -1, Sum19B: -1},
	{Mode: modeRange9Pair, Curr: 25, Prev: 24, Sum9A: 50, Sum9B: 51, Sum19A: -1, Sum19B: -1},
	{Mode: modeRange9Pair, Curr: 26, Prev: 25, Sum9A: 52, Sum9B: 53, Sum19A: -1, Sum19B: -1},
	{Mode: modeRange9Pair, Curr: 27, Prev: 26, Sum9A: 54, Sum9B: 55, Sum19A: -1, Sum19B: -1},
	{Mode: modeRange9Range19, Curr: 28, Prev: 27, Sum9A: 56, Sum9B: -1, Sum19A: 57, Sum19B: -1},
	{Mode: modeRange19Pair, Curr: 29, Prev: 28, Sum9A: -1, Sum9B: -1, Sum19A: 58, Sum19B: 59},
	{Mode: modeRange19Pair, Curr: 30, Prev: 29, Sum9A: -1, Sum9B: -1, Sum19A: 60, Sum19B: 61},
	{Mode: modeRange19Pair, Curr: 31, Prev: 30, Sum9A: -1, Sum9B: -1, Sum19A: 62, Sum19B: 63},
	{Mode: modeRange19Pair, Curr: 32, Prev: 31, Sum9A: -1, Sum9B: -1, Sum19A: 64, Sum19B: 65},
	{Mode: modeRange19Pair, Curr: 33, Prev: 32, Sum9A: -1, Sum9B: -1, Sum19A: 66, Sum19B: 67},
	{Mode: modeRange19Pair, Curr: 34, Prev: 33, Sum9A: -1, Sum9B: -1, Sum19A: 68, Sum19B: 69},
	{Mode: modeRange19Pair, Curr: 35, Prev: 34, Sum9A: -1, Sum9B: -1, Sum19A: 70, Sum19B: 71},
	{Mode: modeRange19Pair, Curr: 36, Prev: 35, Sum9A: -1, Sum9B: -1, Sum19A: 72, Sum19B: 73},
	{Mode: modeRange19Pair, Curr: 37, Prev: 36, Sum9A: -1, Sum9B: -1, Sum19A: 74, Sum19B: 75},
	{Mode: modeRange19Pair, Curr: 38, Prev: 37, Sum9A: -1, Sum9B: -1, Sum19A: 76, Sum19B: 77},
	{Mode: modeRange19Pair, Curr: 39, Prev: 38, Sum9A: -1, Sum9B: -1, Sum19A: 78, Sum19B: 79},
	{Mode: modeRange19Pair, Curr: 40, Prev: 39, Sum9A: -1, Sum9B: -1, Sum19A: 80, Sum19B: 81},
	{Mode: modeRange19Pair, Curr: 41, Prev: 40, Sum9A: -1, Sum9B: -1, Sum19A: 82, Sum19B: 83},
	{Mode: modeRange19Range9, Curr: 42, Prev: 41, Sum9A: 85, Sum9B: -1, Sum19A: 84, Sum19B: -1},
	{Mode: modeRange9Pair, Curr: 43, Prev: 42, Sum9A: 86, Sum9B: 87, Sum19A: -1, Sum19B: -1},
	{Mode: modeRange9Pair, Curr: 44, Prev: 43, Sum9A: 88, Sum9B: 89, Sum19A: -1, Sum19B: -1},
	{Mode: modeRange9Pair, Curr: 45, Prev: 44, Sum9A: 90, Sum9B: 91, Sum19A: -1, Sum19B: -1},
	{Mode: modeRange9Pair, Curr: 46, Prev: 45, Sum9A: 92, Sum9B: 93, Sum19A: -1, Sum19B: -1},
	{Mode: modeRange9Pair, Curr: 47, Prev: 46, Sum9A: 94, Sum9B: 95, Sum19A: -1, Sum19B: -1},
	{Mode: modeRange9Pair, Curr: 48, Prev: 47, Sum9A: 96, Sum9B: 97, Sum19A: -1, Sum19B: -1},
	{Mode: modeRange9Range19, Curr: 49, Prev: 48, Sum9A: 98, Sum9B: -1, Sum19A: 99, Sum19B: -1},
	{Mode: modeRange19Pair, Curr: 50, Prev: 49, Sum9A: -1, Sum9B: -1, Sum19A: 100, Sum19B: 101},
	{Mode: modeRange19Pair, Curr: 51, Prev: 50, Sum9A: -1, Sum9B: -1, Sum19A: 102, Sum19B: 103},
	{Mode: modeRange19Pair, Curr: 52, Prev: 51, Sum9A: -1, Sum9B: -1, Sum19A: 104, Sum19B: 105},
	{Mode: modeRange19Pair, Curr: 53, Prev: 52, Sum9A: -1, Sum9B: -1, Sum19A: 106, Sum19B: 107},
	{Mode: modeRange19Pair, Curr: 54, Prev: 53, Sum9A: -1, Sum9B: -1, Sum19A: 108, Sum19B: 109},
	{Mode: modeRange19Pair, Curr: 55, Prev: 54, Sum9A: -1, Sum9B: -1, Sum19A: 110, Sum19B: 111},
	{Mode: modeRange19Pair, Curr: 56, Prev: 55, Sum9A: -1, Sum9B: -1, Sum19A: 112, Sum19B: 113},
	{Mode: modeRange19Pair, Curr: 57, Prev: 56, Sum9A: -1, Sum9B: -1, Sum19A: 114, Sum19B: 115},
	{Mode: modeRange19Pair, Curr: 58, Prev: 57, Sum9A: -1, Sum9B: -1, Sum19A: 116, Sum19B: 117},
	{Mode: modeRange19Pair, Curr: 59, Prev: 58, Sum9A: -1, Sum9B: -1, Sum19A: 118, Sum19B: 119},
	{Mode: modeRange19Pair, Curr: 60, Prev: 59, Sum9A: -1, Sum9B: -1, Sum19A: 120, Sum19B: 121},
	{Mode: modeRange19Pair, Curr: 61, Prev: 60, Sum9A: -1, Sum9B: -1, Sum19A: 122, Sum19B: 123},
	{Mode: modeRange19Pair, Curr: 62, Prev: 61, Sum9A: -1, Sum9B: -1, Sum19A: 124, Sum19B: 125},
	{Mode: modeRange19Range9, Curr: 63, Prev: 62, Sum9A: 127, Sum9B: -1, Sum19A: 126, Sum19B: -1},
	{Mode: modeRange9Pair, Curr: 64, Prev: 63, Sum9A: 128, Sum9B: 129, Sum19A: -1, Sum19B: -1},
	{Mode: modeRange9Pair, Curr: 65, Prev: 64, Sum9A: 130, Sum9B: 131, Sum19A: -1, Sum19B: -1},
	{Mode: modeRange9Pair, Curr: 66, Prev: 65, Sum9A: 132, Sum9B: 133, Sum19A: -1, Sum19B: -1},
	{Mode: modeRange9Pair, Curr: 67, Prev: 66, Sum9A: 134, Sum9B: 135, Sum19A: -1, Sum19B: -1},
	{Mode: modeRange9Pair, Curr: 68, Prev: 67, Sum9A: 136, Sum9B: 137, Sum19A: -1, Sum19B: -1},
	{Mode: modeRange9Pair, Curr: 69, Prev: 68, Sum9A: 138, Sum9B: 139, Sum19A: -1, Sum19B: -1},
	{Mode: modeRange9Pair, Curr: 70, Prev: 69, Sum9A: 140, Sum9B: 141, Sum19A: -1, Sum19B: -1},
	{Mode: modeRange9Pair, Curr: 71, Prev: 70, Sum9A: 142, Sum9B: 143, Sum19A: -1, Sum19B: -1},
	{Mode: modeRange9Pair, Curr: 72, Prev: 71, Sum9A: 144, Sum9B: 145, Sum19A: -1, Sum19B: -1},
	{Mode: modeRange9Pair, Curr: 73, Prev: 72, Sum9A: 146, Sum9B: 147, Sum19A: -1, Sum19B: -1},
	{Mode: modeRange9Pair, Curr: 74, Prev: 73, Sum9A: 148, Sum9B: 149, Sum19A: -1, Sum19B: -1},
	{Mode: modeRange9Pair, Curr: 75, Prev: 74, Sum9A: 150, Sum9B: 151, Sum19A: -1, Sum19B: -1},
	{Mode: modeRange9Pair, Curr: 76, Prev: 75, Sum9A: 152, Sum9B: 153, Sum19A: -1, Sum19B: -1},
	{Mode: modeRange9Pair, Curr: 77, Prev: 76, Sum9A: 154, Sum9B: 155, Sum19A: -1, Sum19B: -1},
	{Mode: modeRange9Pair, Curr: 78, Prev: 77, Sum9A: 156, Sum9B: 157, Sum19A: -1, Sum19B: -1},
	{Mode: modeRange9Pair, Curr: 79, Prev: 78, Sum9A: 158, Sum9B: 159, Sum19A: -1, Sum19B: -1},
	{Mode: modeRange9Pair, Curr: 80, Prev: 79, Sum9A: 160, Sum9B: 161, Sum19A: -1, Sum19B: -1},
	{Mode: modeRange9Pair, Curr: 81, Prev: 80, Sum9A: 162, Sum9B: 163, Sum19A: -1, Sum19B: -1},
	{Mode: modeRange9Pair, Curr: 82, Prev: 81, Sum9A: 164, Sum9B: 165, Sum19A: -1, Sum19B: -1},
	{Mode: modeRange9Pair, Curr: 83, Prev: 82, Sum9A: 166, Sum9B: 167, Sum19A: -1, Sum19B: -1},
	{Mode: modeRange9Range19, Curr: 84, Prev: 83, Sum9A: 168, Sum9B: -1, Sum19A: 169, Sum19B: -1},
	{Mode: modeRange19Pair, Curr: 85, Prev: 84, Sum9A: -1, Sum9B: -1, Sum19A: 170, Sum19B: 171},
	{Mode: modeRange19Pair, Curr: 86, Prev: 85, Sum9A: -1, Sum9B: -1, Sum19A: 172, Sum19B: 173},
	{Mode: modeRange19Pair, Curr: 87, Prev: 86, Sum9A: -1, Sum9B: -1, Sum19A: 174, Sum19B: 175},
	{Mode: modeRange19Pair, Curr: 88, Prev: 87, Sum9A: -1, Sum9B: -1, Sum19A: 176, Sum19B: 177},
	{Mode: modeRange19Pair, Curr: 89, Prev: 88, Sum9A: -1, Sum9B: -1, Sum19A: 178, Sum19B: 179},
	{Mode: modeRange19Pair, Curr: 90, Prev: 89, Sum9A: -1, Sum9B: -1, Sum19A: 180, Sum19B: 181},
	{Mode: modeRange19Pair, Curr: 91, Prev: 90, Sum9A: -1, Sum9B: -1, Sum19A: 182, Sum19B: 183},
	{Mode: modeRange19Pair, Curr: 92, Prev: 91, Sum9A: -1, Sum9B: -1, Sum19A: 184, Sum19B: 185},
	{Mode: modeRange19Pair, Curr: 93, Prev: 92, Sum9A: -1, Sum9B: -1, Sum19A: 186, Sum19B: 187},
	{Mode: modeRange19Pair, Curr: 94, Prev: 93, Sum9A: -1, Sum9B: -1, Sum19A: 188, Sum19B: 189},
	{Mode: modeRange19Pair, Curr: 95, Prev: 94, Sum9A: -1, Sum9B: -1, Sum19A: 190, Sum19B: 191},
	{Mode: modeRange19Pair, Curr: 96, Prev: 95, Sum9A: -1, Sum9B: -1, Sum19A: 192, Sum19B: 193},
	{Mode: modeRange19Pair, Curr: 97, Prev: 96, Sum9A: -1, Sum9B: -1, Sum19A: 194, Sum19B: 195},
	{Mode: modeRange19Range9, Curr: 98, Prev: 97, Sum9A: 197, Sum9B: -1, Sum19A: 196, Sum19B: -1},
	{Mode: modeRange9Pair, Curr: 99, Prev: 98, Sum9A: 198, Sum9B: 199, Sum19A: -1, Sum19B: -1},
	{Mode: modeRange9Pair, Curr: 100, Prev: 99, Sum9A: 200, Sum9B: 201, Sum19A: -1, Sum19B: -1},
	{Mode: modeRange9Pair, Curr: 101, Prev: 100, Sum9A: 202, Sum9B: 203, Sum19A: -1, Sum19B: -1},
	{Mode: modeRange9Pair, Curr: 102, Prev: 101, Sum9A: 204, Sum9B: 205, Sum19A: -1, Sum19B: -1},
	{Mode: modeRange9Pair, Curr: 103, Prev: 102, Sum9A: 206, Sum9B: 207, Sum19A: -1, Sum19B: -1},
	{Mode: modeRange9Pair, Curr: 104, Prev: 103, Sum9A: 208, Sum9B: 209, Sum19A: -1, Sum19B: -1},
	{Mode: modePartial211, Curr: 105, Prev: 104, Sum9A: 210, Sum9B: -1, Sum19A: -1, Sum19B: -1},
	{Mode: modePartial212, Curr: 106, Prev: 105, Sum9A: -1, Sum9B: -1, Sum19A: -1, Sum19B: -1},
}

type PartialEcMulClaim struct {
	LogSize uints.U8
}

type PartialEcMulInteractionClaim struct {
	ClaimedSum m31.QM31
}

type PartialEcMulComponent struct {
	qm31 *m31.QM31Chip

	pedersenElements     m31.InteractionElements
	rangeCheck9Elements  m31.InteractionElements
	rangeCheck19Elements m31.InteractionElements
	partialEcMulElements m31.InteractionElements

	claimedSum    m31.QM31
	columnSizeInv m31.QM31
	vanishEvalInv m31.QM31
	logSize       uints.U8
}

func NewPartialEcMul(
	api frontend.API,
	qm31Chip *m31.QM31Chip,
	pedersenElements m31.InteractionElements,
	rangeCheck9Elements m31.InteractionElements,
	rangeCheck19Elements m31.InteractionElements,
	partialEcMulElements m31.InteractionElements,
	vanishEvalInv m31.QM31,
	claim PartialEcMulClaim,
	interactionClaim PartialEcMulInteractionClaim,
) *PartialEcMulComponent {
	columnSize := computeColumnSize(api, claim.LogSize)

	return &PartialEcMulComponent{
		qm31:                 qm31Chip,
		pedersenElements:     pedersenElements,
		rangeCheck9Elements:  rangeCheck9Elements,
		rangeCheck19Elements: rangeCheck19Elements,
		partialEcMulElements: partialEcMulElements,
		claimedSum:           interactionClaim.ClaimedSum,
		columnSizeInv:        qm31Chip.Inverse(columnSize),
		vanishEvalInv:        vanishEvalInv,
		logSize:              claim.LogSize,
	}
}

func (c *PartialEcMulComponent) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 { // FORMAT
	traceSampledValues, interactionSampledValues := traces.Take(partialEcMulTraceColumns, partialEcMulInteractionColumns)

	// ╔══════════════════════════════════╗
	// ║        Preprocessed Trace        ║
	// ╚══════════════════════════════════╝
	// (none)

	// ╔══════════════════════════════════╗
	// ║            Main Trace            ║
	// ╚══════════════════════════════════╝
	// Read via indexed helpers instead of a cursor.
	inputLimbs := traceSampledValues.Slice(0, 73)

	// Pedersen outputs
	pedersenOutputs := traceSampledValues.Slice(73, 56)

	// Subsequent blocks are sized arrays with trailing PBits/coeffs.
	var subDiff1 [28]m31.QM31
	copy(subDiff1[:], traceSampledValues.Slice(129, 28))
	subDiff1PBit := traceSampledValues.Get(157)

	var addRes [28]m31.QM31
	copy(addRes[:], traceSampledValues.Slice(158, 28))
	addResPBit := traceSampledValues.Get(186)

	var subDiff2 [28]m31.QM31
	copy(subDiff2[:], traceSampledValues.Slice(187, 28))
	subDiff2PBit := traceSampledValues.Get(215)

	var divRes [28]m31.QM31
	copy(divRes[:], traceSampledValues.Slice(216, 28))
	divK := traceSampledValues.Get(244)

	var divCarries [27]m31.QM31
	copy(divCarries[:], traceSampledValues.Slice(245, 27))

	var mul1Res [28]m31.QM31
	copy(mul1Res[:], traceSampledValues.Slice(272, 28))
	mul1K := traceSampledValues.Get(300)

	var mul1Carries [27]m31.QM31
	copy(mul1Carries[:], traceSampledValues.Slice(301, 27))

	var subDiff3 [28]m31.QM31
	copy(subDiff3[:], traceSampledValues.Slice(328, 28))
	subDiff3PBit := traceSampledValues.Get(356)

	var subDiff4 [28]m31.QM31
	copy(subDiff4[:], traceSampledValues.Slice(357, 28))
	subDiff4PBit := traceSampledValues.Get(385)

	var mul2Res [28]m31.QM31
	copy(mul2Res[:], traceSampledValues.Slice(386, 28))
	mul2K := traceSampledValues.Get(414)

	var mul2Carries [27]m31.QM31
	copy(mul2Carries[:], traceSampledValues.Slice(415, 27))

	var subDiff5 [28]m31.QM31
	copy(subDiff5[:], traceSampledValues.Slice(442, 28))
	subDiff5PBit := traceSampledValues.Get(470)

	enabler := traceSampledValues.Get(471)

	// ╔══════════════════════════════════╗
	// ║         Interaction Trace        ║
	// ╚══════════════════════════════════╝
	groupVals := make([]m31.QM31, partialEcMulGroupCount)
	for g := 0; g < partialEcMulGroupCount-1; g++ {
		groupVals[g] = interactionSampledValues.Partial(c.qm31, g*4, 0)
	}
	// Last group (start=424) has previous/current samples.
	groupVals[partialEcMulGroupCount-1] = interactionSampledValues.Partial(c.qm31, 424, 1)
	negGroup := interactionSampledValues.Partial(c.qm31, 424, 0)

	// ╔══════════════════════════════════╗
	// ║       Constraint Evaluations     ║
	// ╚══════════════════════════════════╝

	// Enabler constraint
	enablerSq := c.qm31.Mul(enabler, enabler)
	enablerConstraint := c.qm31.Sub(enablerSq, enabler)
	enablerConstraint = c.qm31.Mul(enablerConstraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, enablerConstraint)

	// Pedersen lookup sum
	scale262144 := m31.NewQM31FromM31(m31.NewM31Unchecked(262144))
	firstValue := c.qm31.Add(inputLimbs[2], c.qm31.Mul(scale262144, inputLimbs[1]))
	firstValue = c.qm31.Add(firstValue, inputLimbs[3])
	values := make([]m31.QM31, 0, 57)
	values = append(values, firstValue)
	values = append(values, pedersenOutputs[:]...)
	pedersenSum, err := c.qm31.Combine(c.pedersenElements, values)
	if err != nil {
		panic(err)
	}

	// EC add evaluation
	var ecInputs sub.ECAddInputs
	for i := 0; i < 28; i++ {
		ecInputs.X1[i] = inputLimbs[17+i]
		ecInputs.Y1[i] = inputLimbs[17+28+i]
		ecInputs.X2[i] = pedersenOutputs[i]
		ecInputs.Y2[i] = pedersenOutputs[28+i]
	}

	ecTrace := sub.ECAddTrace{
		SubDiff1:     subDiff1,
		SubDiff1PBit: subDiff1PBit,
		AddRes:       addRes,
		AddResPBit:   addResPBit,
		SubDiff2:     subDiff2,
		SubDiff2PBit: subDiff2PBit,
		DivRes:       divRes,
		DivK:         divK,
		DivCarries:   divCarries,
		Mul1Res:      mul1Res,
		Mul1K:        mul1K,
		Mul1Carries:  mul1Carries,
		SubDiff3:     subDiff3,
		SubDiff3PBit: subDiff3PBit,
		SubDiff4:     subDiff4,
		SubDiff4PBit: subDiff4PBit,
		Mul2Res:      mul2Res,
		Mul2K:        mul2K,
		Mul2Carries:  mul2Carries,
		SubDiff5:     subDiff5,
		SubDiff5PBit: subDiff5PBit,
	}

	ecResult := sub.ECAddEvaluate(
		c.qm31,
		ecInputs,
		ecTrace,
		c.rangeCheck9Elements,
		c.rangeCheck19Elements,
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)
	sum = ecResult.Sum
	range9 := ecResult.RangeCheck9Sums
	range19 := ecResult.RangeCheck19Sums
	extraRange210, err := c.qm31.Combine(c.rangeCheck9Elements, []m31.QM31{subDiff5[26], subDiff5[27]})
	if err != nil {
		panic(err)
	}
	range9[210] = extraRange210

	setRange9 := func(index int, a, b m31.QM31) {
		val, err := c.qm31.Combine(c.rangeCheck9Elements, []m31.QM31{a, b})
		if err != nil {
			panic(err)
		}
		range9[index] = val
	}
	setRange9(56, mul2Carries[23], mul2Carries[24])
	setRange9(85, subDiff5[26], subDiff5[27])
	setRange9(98, pedersenOutputs[18], pedersenOutputs[19])
	setRange9(127, pedersenOutputs[48], pedersenOutputs[49])
	setRange9(168, pedersenOutputs[17], pedersenOutputs[18])
	setRange9(197, pedersenOutputs[47], pedersenOutputs[48])

	setRange19WithOffset := func(index int, value m31.QM31, offset uint64) {
		offsetQM := m31.NewQM31FromM31(m31.NewM31Unchecked(offset))
		val, err := c.qm31.Combine(c.rangeCheck19Elements, []m31.QM31{c.qm31.Add(value, offsetQM)})
		if err != nil {
			panic(err)
		}
		range19[index] = val
	}
	setRange19WithOffset(57, mul2Carries[25], 262144)
	setRange19WithOffset(58, mul2Carries[26], 131072)
	setRange19WithOffset(84, subDiff5[25], 131072)
	setRange19WithOffset(99, pedersenOutputs[19], 262144)
	setRange19WithOffset(126, pedersenOutputs[47], 131072)
	setRange19WithOffset(169, pedersenOutputs[19], 262144)
	setRange19WithOffset(196, pedersenOutputs[46], 131072)

	// Partial EC mul lookup sums
	partialSum211, err := c.qm31.Combine(c.partialEcMulElements, inputLimbs)
	if err != nil {
		panic(err)
	}
	values = values[:0]
	one := c.qm31.One()
	zero := c.qm31.Zero()
	values = append(values, inputLimbs[0])
	values = append(values, c.qm31.Add(inputLimbs[1], one))
	values = append(values, inputLimbs[2])
	values = append(values, inputLimbs[4], inputLimbs[5], inputLimbs[6], inputLimbs[7], inputLimbs[8], inputLimbs[9])
	values = append(values, inputLimbs[10], inputLimbs[11], inputLimbs[12], inputLimbs[13], inputLimbs[14], inputLimbs[15], inputLimbs[16])
	values = append(values, zero)
	values = append(values, subDiff3[:]...)
	values = append(values, subDiff5[:]...)
	partialSum212, err := c.qm31.Combine(c.partialEcMulElements, values)
	if err != nil {
		panic(err)
	}

	getRange9 := func(index int) m31.QM31 {
		if index < 0 {
			return zero
		}
		if index >= len(range9) {
			panic("range9 index out of bounds")
		}
		return range9[index]
	}

	getRange19 := func(index int) m31.QM31 {
		if index < 0 {
			return zero
		}
		if index >= len(range19) {
			panic("range19 index out of bounds")
		}
		return range19[index]
	}

	for _, spec := range constraintSpecs {
		curr := groupVals[spec.Curr]
		var prevValue m31.QM31
		if spec.Prev >= 0 {
			prevValue = groupVals[spec.Prev]
		} else {
			prevValue = zero
		}

		switch spec.Mode {
		case modePedersen:
			sumA := pedersenSum
			sumB := getRange9(spec.Sum9A)

			tmp := c.qm31.Mul(curr, sumA)
			tmp = c.qm31.Mul(tmp, sumB)
			tmp = c.qm31.Sub(tmp, sumA)
			tmp = c.qm31.Sub(tmp, sumB)
			tmp = c.qm31.Mul(tmp, c.vanishEvalInv)
			sum = accumulateConstraint(c.qm31, sum, randomCoeff, tmp)

		case modeRange9Pair:
			sumA := getRange9(spec.Sum9A)
			sumB := getRange9(spec.Sum9B)

			tmp := c.qm31.Sub(curr, prevValue)
			tmp = c.qm31.Mul(tmp, sumA)
			tmp = c.qm31.Mul(tmp, sumB)
			tmp = c.qm31.Sub(tmp, sumA)
			tmp = c.qm31.Sub(tmp, sumB)
			tmp = c.qm31.Mul(tmp, c.vanishEvalInv)
			sum = accumulateConstraint(c.qm31, sum, randomCoeff, tmp)

		case modeRange19Pair:
			sumA := getRange19(spec.Sum19A)
			sumB := getRange19(spec.Sum19B)

			tmp := c.qm31.Sub(curr, prevValue)
			tmp = c.qm31.Mul(tmp, sumA)
			tmp = c.qm31.Mul(tmp, sumB)
			tmp = c.qm31.Sub(tmp, sumA)
			tmp = c.qm31.Sub(tmp, sumB)
			tmp = c.qm31.Mul(tmp, c.vanishEvalInv)
			sum = accumulateConstraint(c.qm31, sum, randomCoeff, tmp)

		case modeRange9Range19:
			sumA := getRange9(spec.Sum9A)
			sumB := getRange19(spec.Sum19A)

			tmp := c.qm31.Sub(curr, prevValue)
			tmp = c.qm31.Mul(tmp, sumA)
			tmp = c.qm31.Mul(tmp, sumB)
			tmp = c.qm31.Sub(tmp, sumA)
			tmp = c.qm31.Sub(tmp, sumB)
			tmp = c.qm31.Mul(tmp, c.vanishEvalInv)
			sum = accumulateConstraint(c.qm31, sum, randomCoeff, tmp)

		case modeRange19Range9:
			sumA := getRange19(spec.Sum19A)
			sumB := getRange9(spec.Sum9A)

			tmp := c.qm31.Sub(curr, prevValue)
			tmp = c.qm31.Mul(tmp, sumA)
			tmp = c.qm31.Mul(tmp, sumB)
			tmp = c.qm31.Sub(tmp, sumA)
			tmp = c.qm31.Sub(tmp, sumB)
			tmp = c.qm31.Mul(tmp, c.vanishEvalInv)
			sum = accumulateConstraint(c.qm31, sum, randomCoeff, tmp)

		case modePartial211:
			sumA := getRange9(spec.Sum9A)

			tmp := c.qm31.Sub(curr, prevValue)
			tmp = c.qm31.Mul(tmp, sumA)
			tmp = c.qm31.Mul(tmp, partialSum211)
			tmp = c.qm31.Sub(tmp, c.qm31.Mul(sumA, enabler))
			tmp = c.qm31.Sub(tmp, partialSum211)
			tmp = c.qm31.Mul(tmp, c.vanishEvalInv)
			sum = accumulateConstraint(c.qm31, sum, randomCoeff, tmp)

		case modePartial212:
			tmp := c.qm31.Sub(curr, prevValue)
			tmp = c.qm31.Sub(tmp, negGroup)
			tmp = c.qm31.Add(tmp, c.qm31.Mul(c.claimedSum, c.columnSizeInv))
			tmp = c.qm31.Mul(tmp, partialSum212)
			tmp = c.qm31.Add(tmp, enabler)
			tmp = c.qm31.Mul(tmp, c.vanishEvalInv)
			sum = accumulateConstraint(c.qm31, sum, randomCoeff, tmp)
		}
	}
	return sum
}
