package cairo_components

import (
	sub "github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components/subroutines"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
)

const (
	AddModBuiltinTraceColumns       = 251
	AddModBuiltinInteractionColumns = 108
)

type AddModBuiltinClaim struct {
	LogSize                   frontend.Variable
	AddModBuiltinSegmentStart frontend.Variable
}

type AddModBuiltinInteractionClaim struct {
	ClaimedSum m31.QM31
}

type AddModBuiltinComponent struct {
	api  frontend.API
	qm31 *m31.QM31Chip

	logSize frontend.Variable

	memoryAddressToIdElems m31.InteractionElements
	memoryIdToBigElems     m31.InteractionElements

	segmentStart  m31.QM31
	claimedSum    m31.QM31
	columnSizeInv m31.QM31
	vanishEvalInv m31.QM31
}

func NewAddModBuiltin(
	api frontend.API,
	qm31 *m31.QM31Chip,
	memoryAddressElements m31.InteractionElements,
	memoryIdElements m31.InteractionElements,
	vanishEvalInv m31.QM31,
	claim AddModBuiltinClaim,
	interactionClaim AddModBuiltinInteractionClaim,
) AddModBuiltinComponent {
	columnSize := computeColumnSize(api, claim.LogSize)
	columnSizeInv := qm31.Inverse(columnSize)

	segmentStart := m31.NewQM31FromM31(
		m31.NewM31Unchecked(claim.AddModBuiltinSegmentStart),
	)

	return AddModBuiltinComponent{
		api:                    api,
		qm31:                   qm31,
		logSize:                claim.LogSize,
		memoryAddressToIdElems: memoryAddressElements,
		memoryIdToBigElems:     memoryIdElements,
		segmentStart:           segmentStart,
		claimedSum:             interactionClaim.ClaimedSum,
		columnSizeInv:          columnSizeInv,
		vanishEvalInv:          vanishEvalInv,
	}
}

func (c AddModBuiltinComponent) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	traceSampledValues, interactionSampledValues := traces.Take(AddModBuiltinTraceColumns, AddModBuiltinInteractionColumns)

	// ╔══════════════════════════════════╗
	// ║        Preprocessed Trace        ║
	// ╚══════════════════════════════════╝
	seq := traces.Get(NewPreprocessedColumnSeq(c.api, c.logSize))

	// ╔══════════════════════════════════╗
	// ║            Main Trace            ║
	// ╚══════════════════════════════════╝
	readPoint := func(idIndex int) sub.ModPoint {
		point := sub.ModPoint{ID: traceSampledValues.Get(idIndex)}
		for i := 0; i < 11; i++ {
			point.Limbs[i] = traceSampledValues.Get(idIndex + 1 + i)
		}
		return point
	}

	readPointer3 := func(idIndex int) sub.Pointer3 {
		return sub.Pointer3{
			ID: traceSampledValues.Get(idIndex),
			Limbs: [3]m31.QM31{
				traceSampledValues.Get(idIndex + 1),
				traceSampledValues.Get(idIndex + 2),
				traceSampledValues.Get(idIndex + 3),
			},
		}
	}

	readOffset := func(start int) sub.OffsetEntry {
		return sub.OffsetEntry{
			ID:          traceSampledValues.Get(start),
			MSB:         traceSampledValues.Get(start + 1),
			MidLimbsSet: traceSampledValues.Get(start + 2),
			Limbs: [3]m31.QM31{
				traceSampledValues.Get(start + 3),
				traceSampledValues.Get(start + 4),
				traceSampledValues.Get(start + 5),
			},
		}
	}

	isInstanceZero := traceSampledValues.Get(0)

	points := [4]sub.ModPoint{
		readPoint(1),
		readPoint(13),
		readPoint(25),
		readPoint(37),
	}

	valuesPtr := readPointer3(49)
	offsetsPtr := readPointer3(53)
	offsetsPtrPrev := readPointer3(57)
	nPtr := readPointer3(61)
	nPtrPrev := readPointer3(65)

	valuesPtrPrevID := traceSampledValues.Get(69)

	prevPointIDs := [4]m31.QM31{traceSampledValues.Get(70), traceSampledValues.Get(71), traceSampledValues.Get(72), traceSampledValues.Get(73)}

	offsets := [3]sub.OffsetEntry{readOffset(74), readOffset(80), readOffset(86)}

	aPoints := [4]sub.ModPoint{
		readPoint(92),
		readPoint(104),
		readPoint(116),
		readPoint(128),
	}

	bPoints := [4]sub.ModPoint{
		readPoint(140),
		readPoint(152),
		readPoint(164),
		readPoint(176),
	}

	cPoints := [4]sub.ModPoint{
		readPoint(188),
		readPoint(200),
		readPoint(212),
		readPoint(224),
	}

	subPBit := traceSampledValues.Get(236)

	var carries [14]m31.QM31
	for i := 0; i < 14; i++ {
		carries[i] = traceSampledValues.Get(237 + i)
	}

	// ╔══════════════════════════════════╗
	// ║         Interaction Trace        ║
	// ╚══════════════════════════════════╝

	// Use InteractionTrace.Partial to build current/previous partials.
	partials := make([]m31.QM31, 27)
	for i := 0; i < 26; i++ {
		partials[i] = interactionSampledValues.Partial(c.qm31, i*4, 0)
	}
	// Last block (start=104) has previous/current samples.
	partials[26] = interactionSampledValues.Partial(c.qm31, 104, 1)
	prevLastPartial := interactionSampledValues.Partial(c.qm31, 104, 0)

	// ╔══════════════════════════════════╗
	// ║       Constraint Evaluations     ║
	// ╚══════════════════════════════════╝

	modInput := sub.ModUtilsInputs{
		BaseAddress:        c.segmentStart,
		InstanceNum:        seq,
		IsInstanceZero:     isInstanceZero,
		Points:             points,
		PrevPointIDs:       prevPointIDs,
		ValuesPointer:      valuesPtr,
		OffsetsPointer:     offsetsPtr,
		OffsetsPointerPrev: offsetsPtrPrev,
		ValuesPointerPrev:  valuesPtrPrevID,
		NPointer:           nPtr,
		NPointerPrev:       nPtrPrev,
		Offsets:            offsets,
		A:                  aPoints,
		B:                  bPoints,
		C:                  cPoints,
	}

	res := sub.ModUtilsEvaluate(
		c.qm31,
		modInput,
		c.memoryAddressToIdElems,
		c.memoryIdToBigElems,
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)
	sum = res.Sum

	addressSums := res.AddressLookupSums
	idSums := res.IdToBigLookupSums

	if len(addressSums) != 29 {
		panic("unexpected number of address lookup sums for add_mod_builtin")
	}
	if len(idSums) != 24 {
		panic("unexpected number of id-to-big lookup sums for add_mod_builtin")
	}

	one := c.qm31.One()

	// sub_p_bit is boolean.
	constraint := c.qm31.Mul(c.qm31.Sub(subPBit, one), subPBit)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	// carry limbs are in {-1, 0, 1}.
	for _, carry := range carries {
		quadratic := c.qm31.Sub(c.qm31.Mul(carry, carry), one)
		carryConstraint := c.qm31.Mul(carry, quadratic)
		carryConstraint = c.qm31.Mul(carryConstraint, c.vanishEvalInv)
		sum = accumulateConstraint(c.qm31, sum, randomCoeff, carryConstraint)
	}

	// Last carry must vanish.
	a3 := aPoints[3]
	b3 := bPoints[3]
	c3 := cPoints[3]
	p3 := points[3]

	lastCarry := carries[13]
	topCarry := c.qm31.Add(
		lastCarry,
		c.qm31.Sub(
			c.qm31.Sub(
				c.qm31.Add(a3.Limbs[9], b3.Limbs[9]),
				c3.Limbs[9],
			),
			c.qm31.Mul(p3.Limbs[9], subPBit),
		),
	)
	topCarry = c.qm31.Add(
		topCarry,
		c.qm31.Mul(
			qm31Const(512),
			c.qm31.Sub(
				c.qm31.Sub(
					c.qm31.Add(a3.Limbs[10], b3.Limbs[10]),
					c3.Limbs[10],
				),
				c.qm31.Mul(p3.Limbs[10], subPBit),
			),
		),
	)
	topCarry = c.qm31.Mul(topCarry, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, topCarry)

	sum = addModBuiltinLookupConstraints(
		c.qm31,
		sum,
		randomCoeff,
		c.vanishEvalInv,
		c.claimedSum,
		c.columnSizeInv,
		partials,
		prevLastPartial,
		addressSums,
		idSums,
	)

	return sum
}

func addModBuiltinLookupConstraints(
	qm31 *m31.QM31Chip,
	sum m31.QM31,
	randomCoeff m31.QM31,
	vanishEvalInv m31.QM31,
	claimedSum m31.QM31,
	columnSizeInv m31.QM31,
	partials []m31.QM31,
	prevLastPartial m31.QM31,
	addressSums []m31.QM31,
	idSums []m31.QM31,
) m31.QM31 {

	addrIdx := 0
	idIdx := 0

	firstAddr := addressSums[addrIdx]
	firstID := idSums[idIdx]
	addrIdx++
	idIdx++

	constraint := qm31.Mul(partials[0], qm31.Mul(firstAddr, firstID))
	constraint = qm31.Sub(constraint, qm31.Add(firstAddr, firstID))
	constraint = qm31.Mul(constraint, vanishEvalInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	for i := 1; i <= 8; i++ {
		addr := addressSums[addrIdx]
		id := idSums[idIdx]
		addrIdx++
		idIdx++

		diff := qm31.Sub(partials[i], partials[i-1])
		constraint = qm31.Mul(diff, qm31.Mul(addr, id))
		constraint = qm31.Sub(constraint, qm31.Add(addr, id))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	for i := 0; i < 3; i++ {
		addrA := addressSums[addrIdx]
		addrB := addressSums[addrIdx+1]
		addrIdx += 2

		curr := partials[9+i]
		prev := partials[8+i]
		diff := qm31.Sub(curr, prev)

		constraint = qm31.Mul(diff, qm31.Mul(addrA, addrB))
		constraint = qm31.Sub(constraint, qm31.Add(addrA, addrB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	for k := 12; k <= 25; k++ {
		addr := addressSums[addrIdx]
		id := idSums[idIdx]
		addrIdx++
		idIdx++

		diff := qm31.Sub(partials[k], partials[k-1])
		constraint = qm31.Mul(diff, qm31.Mul(addr, id))
		constraint = qm31.Sub(constraint, qm31.Add(addr, id))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	lastID := idSums[idIdx]
	diff := qm31.Sub(partials[26], partials[25])
	diff = qm31.Sub(diff, prevLastPartial)
	diff = qm31.Add(diff, qm31.Mul(claimedSum, columnSizeInv))

	constraint = qm31.Mul(diff, lastID)
	constraint = qm31.Sub(constraint, qm31.One())
	constraint = qm31.Mul(constraint, vanishEvalInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	return sum
}
