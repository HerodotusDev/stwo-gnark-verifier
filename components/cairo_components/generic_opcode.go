package cairo_components

import (
	"fmt"

	sub "github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components/subroutines"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
)

const (
	genericOpcodeTraceColumns       = 236
	genericOpcodeInteractionColumns = 132
)

type GenericOpcodeClaim struct {
	LogSize uint32
}

type GenericOpcodeInteractionClaim struct {
	ClaimedSum m31.QM31
}

type GenericOpcodeComponent struct {
	qm31 *m31.QM31Chip

	verifyInstructionElements m31.InteractionElements
	memoryAddressToIdElements m31.InteractionElements
	memoryIdToBigElements     m31.InteractionElements
	rangeCheck99Elements      m31.InteractionElements
	rangeCheck19Elements      m31.InteractionElements
	opcodesElements           m31.InteractionElements

	claimedSum    m31.QM31
	columnSizeInv m31.QM31
	vanishEvalInv m31.QM31
}

func NewGenericOpcode(
	qm31 *m31.QM31Chip,
	verifyInstructionElements m31.InteractionElements,
	memoryAddressToIdElements m31.InteractionElements,
	memoryIdToBigElements m31.InteractionElements,
	rangeCheck99Elements m31.InteractionElements,
	rangeCheck19Elements m31.InteractionElements,
	opcodesElements m31.InteractionElements,
	claim GenericOpcodeClaim,
	interactionClaim GenericOpcodeInteractionClaim,
) *GenericOpcodeComponent {
	columnSize := uint32(1)
	if claim.LogSize > 0 {
		columnSize <<= claim.LogSize
	}
	columnSizeQM := m31.NewQM31FromM31(m31.NewM31Unchecked(uint64(columnSize)))
	columnSizeInv := qm31.Inverse(columnSizeQM)

	return &GenericOpcodeComponent{
		qm31:                      qm31,
		verifyInstructionElements: verifyInstructionElements,
		memoryAddressToIdElements: memoryAddressToIdElements,
		memoryIdToBigElements:     memoryIdToBigElements,
		rangeCheck99Elements:      rangeCheck99Elements,
		rangeCheck19Elements:      rangeCheck19Elements,
		opcodesElements:           opcodesElements,
		claimedSum:                interactionClaim.ClaimedSum,
		columnSizeInv:             columnSizeInv,
		vanishEvalInv:             qm31.One(),
	}
}

func (c *GenericOpcodeComponent) Evaluate(
	sum m31.QM31,
	preprocessedSampledValues PreprocessedSampledValues,
	traceSampledValues [][]m31.QM31,
	interactionSampledValues [][]m31.QM31,
	randomCoeff m31.QM31,
) m31.QM31 {
	_ = preprocessedSampledValues

	if len(traceSampledValues) != genericOpcodeTraceColumns {
		panic(fmt.Sprintf("generic opcode expects %d trace columns, got %d", genericOpcodeTraceColumns, len(traceSampledValues)))
	}

	traceVals := make([]m31.QM31, genericOpcodeTraceColumns)
	for i := 0; i < genericOpcodeTraceColumns; i++ {
		if len(traceSampledValues[i]) != 1 {
			panic(fmt.Sprintf("generic opcode trace column %d expected 1 sample, got %d", i, len(traceSampledValues[i])))
		}
		traceVals[i] = traceSampledValues[i][0]
	}

	if len(interactionSampledValues) != genericOpcodeInteractionColumns {
		panic(fmt.Sprintf("generic opcode expects %d interaction columns, got %d", genericOpcodeInteractionColumns, len(interactionSampledValues)))
	}

	enabler := traceVals[235]
	enablerConstraint := c.qm31.Sub(c.qm31.Mul(enabler, enabler), enabler)
	enablerConstraint = c.qm31.Mul(enablerConstraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, enablerConstraint)

	offsets := [3]m31.QM31{traceVals[3], traceVals[4], traceVals[5]}
	decode := sub.DecodeGenericInstructionEvaluate(
		c.qm31,
		traceVals[0],
		offsets,
		traceVals[6],
		traceVals[7],
		traceVals[8],
		traceVals[9],
		traceVals[10],
		traceVals[11],
		traceVals[12],
		traceVals[13],
		traceVals[14],
		traceVals[15],
		traceVals[16],
		traceVals[17],
		traceVals[18],
		traceVals[19],
		traceVals[20],
		c.verifyInstructionElements,
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)
	sum = decode.Sum

	verifyInstructionSum := decode.Instruction.VerifySum
	outputs := decode.Outputs

	op1SrcIndicator := outputs[0]
	resLogicFlag := outputs[1]
	pcUpdateFlag := outputs[2]
	fpUpdateFlag := outputs[3]
	op1ImmPlusOne := outputs[4]
	offset0MinusBase := outputs[5]
	offset1MinusBase := outputs[6]
	offset2MinusBase := outputs[7]

	dstLimbs := gatherLimbs(traceSampledValues, 23, 28)
	op0Limbs := gatherLimbs(traceSampledValues, 53, 28)
	op1Limbs := gatherLimbs(traceSampledValues, 83, 28)
	addResLimbs := gatherLimbs(traceSampledValues, 111, 28)
	mulResLimbs := gatherLimbs(traceSampledValues, 140, 28)
	carries := gatherLimbs(traceSampledValues, 169, 27)
	resLimbs := gatherLimbs(traceSampledValues, 196, 28)

	evalParams := sub.EvalOperandsParams{
		InputPC:          traceVals[0],
		InputAP:          traceVals[1],
		InputFP:          traceVals[2],
		DstBaseFP:        traceVals[6],
		Op0BaseFP:        traceVals[7],
		Op1Imm:           traceVals[8],
		Op1BaseFP:        traceVals[9],
		Op1BaseAP:        traceVals[10],
		ResAddFlag:       traceVals[11],
		ResMulFlag:       traceVals[12],
		PcUpdateJnz:      traceVals[15],
		Op1SrcIndicator:  op1SrcIndicator,
		ResLogicFlag:     resLogicFlag,
		Offset0MinusBase: offset0MinusBase,
		Offset1MinusBase: offset1MinusBase,
		Offset2MinusBase: offset2MinusBase,
	}

	evalRes := sub.EvalOperandsEvaluate(
		c.qm31,
		evalParams,
		traceVals[21],
		traceVals[22],
		dstLimbs,
		traceVals[51],
		traceVals[52],
		op0Limbs,
		traceVals[81],
		traceVals[82],
		op1Limbs,
		addResLimbs,
		traceVals[139],
		mulResLimbs,
		traceVals[168],
		carries,
		resLimbs,
		c.memoryAddressToIdElements,
		c.memoryIdToBigElements,
		c.rangeCheck99Elements,
		c.rangeCheck19Elements,
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)
	sum = evalRes.Sum

	handleInputs := sub.HandleOpcodesInputs{
		InputPC:          traceVals[0],
		InputFP:          traceVals[2],
		DstBaseFP:        traceVals[6],
		Op0BaseFP:        traceVals[7],
		Op1BaseFP:        traceVals[9],
		PcUpdateJump:     traceVals[13],
		OpcodeCall:       traceVals[18],
		OpcodeRet:        traceVals[19],
		OpcodeAssertEq:   traceVals[20],
		ResLogicFlag:     resLogicFlag,
		Op1ImmPlusOne:    op1ImmPlusOne,
		Offset0MinusBase: offset0MinusBase,
		Offset1MinusBase: offset1MinusBase,
		Offset2MinusBase: offset2MinusBase,
	}

	sum = sub.HandleOpcodesEvaluate(
		c.qm31,
		handleInputs,
		dstLimbs,
		op0Limbs,
		resLimbs,
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)

	updateInputs := sub.UpdateRegistersInputs{
		InputPC:         traceVals[0],
		InputAP:         traceVals[1],
		InputFP:         traceVals[2],
		PcUpdateJump:    traceVals[13],
		PcUpdateJumpRel: traceVals[14],
		PcUpdateJnz:     traceVals[15],
		ApUpdateAdd:     traceVals[16],
		ApUpdateAdd1:    traceVals[17],
		OpcodeCall:      traceVals[18],
		OpcodeRet:       traceVals[19],
		PcUpdateFlag:    pcUpdateFlag,
		FpUpdateFlag:    fpUpdateFlag,
		Op1ImmPlusOne:   op1ImmPlusOne,
	}

	sum = sub.UpdateRegistersEvaluate(
		c.qm31,
		updateInputs,
		dstLimbs,
		op1Limbs,
		resLimbs,
		traceVals[224],
		traceVals[225],
		traceVals[226],
		traceVals[227],
		traceVals[228],
		traceVals[229],
		traceVals[230],
		traceVals[231],
		traceVals[232],
		traceVals[233],
		traceVals[234],
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)

	opcodesSum63, err := c.qm31.Combine(c.opcodesElements, []m31.QM31{traceVals[0], traceVals[1], traceVals[2]})
	if err != nil {
		panic(err)
	}
	opcodesSum64, err := c.qm31.Combine(c.opcodesElements, []m31.QM31{traceVals[232], traceVals[233], traceVals[234]})
	if err != nil {
		panic(err)
	}

	fmt.Println("go_debug sum_before_lookup", sum)
	fmt.Println("go_debug verify_instruction_sum", verifyInstructionSum)
	fmt.Println("go_debug memory_address_sums", evalRes.MemoryAddressSums)

	sum = c.lookupConstraints(
		sum,
		c.vanishEvalInv,
		randomCoeff,
		enabler,
		c.claimedSum,
		c.columnSizeInv,
		verifyInstructionSum,
		evalRes.MemoryAddressSums,
		evalRes.MemoryIdSums,
		evalRes.RangeCheck99,
		evalRes.RangeCheck19,
		opcodesSum63,
		opcodesSum64,
		interactionSampledValues,
	)

	fmt.Println("go_debug final_sum", sum)

	return sum
}

func (c *GenericOpcodeComponent) lookupConstraints(
	sum m31.QM31,
	domainVanishInv m31.QM31,
	randomCoeff m31.QM31,
	enabler m31.QM31,
	claimedSum m31.QM31,
	columnSizeInv m31.QM31,
	verifyInstructionSum m31.QM31,
	memoryAddressSums [3]m31.QM31,
	memoryIdSums [3]m31.QM31,
	rangeCheck99 [28]m31.QM31,
	rangeCheck19 [28]m31.QM31,
	opcodesSum63 m31.QM31,
	opcodesSum64 m31.QM31,
	interactionValues [][]m31.QM31,
) m31.QM31 {
	c.qm31.Println(sum)
	if len(interactionValues) != genericOpcodeInteractionColumns {
		panic(fmt.Sprintf("generic opcode expects %d interaction columns, got %d", genericOpcodeInteractionColumns, len(interactionValues)))
	}

	partials := make([]m31.QM31, 33)
	for i := 0; i < 32; i++ {
		base := 4 * i
		for j := 0; j < 4; j++ {
			if len(interactionValues[base+j]) != 1 {
				panic(fmt.Sprintf("interaction column %d expected 1 sample", base+j))
			}
		}
		partials[i] = c.qm31.FromPartialEvals(
			interactionValues[base][0],
			interactionValues[base+1][0],
			interactionValues[base+2][0],
			interactionValues[base+3][0],
		)
	}

	for i := 128; i < 132; i++ {
		if len(interactionValues[i]) != 2 {
			panic(fmt.Sprintf("interaction column %d expected 2 samples", i))
		}
	}

	partials[32] = c.qm31.FromPartialEvals(
		interactionValues[128][1],
		interactionValues[129][1],
		interactionValues[130][1],
		interactionValues[131][1],
	)
	prevPartial := c.qm31.FromPartialEvals(
		interactionValues[128][0],
		interactionValues[129][0],
		interactionValues[130][0],
		interactionValues[131][0],
	)

	constraint := c.qm31.Mul(partials[0], c.qm31.Mul(verifyInstructionSum, memoryAddressSums[0]))
	constraint = c.qm31.Sub(constraint, verifyInstructionSum)
	constraint = c.qm31.Sub(constraint, memoryAddressSums[0])
	constraint = c.qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	diff := c.qm31.Sub(partials[1], partials[0])
	constraint = c.qm31.Mul(diff, c.qm31.Mul(memoryIdSums[0], memoryAddressSums[1]))
	constraint = c.qm31.Sub(constraint, memoryIdSums[0])
	constraint = c.qm31.Sub(constraint, memoryAddressSums[1])
	constraint = c.qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	diff = c.qm31.Sub(partials[2], partials[1])
	constraint = c.qm31.Mul(diff, c.qm31.Mul(memoryIdSums[1], memoryAddressSums[2]))
	constraint = c.qm31.Sub(constraint, memoryIdSums[1])
	constraint = c.qm31.Sub(constraint, memoryAddressSums[2])
	constraint = c.qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	diff = c.qm31.Sub(partials[3], partials[2])
	constraint = c.qm31.Mul(diff, c.qm31.Mul(memoryIdSums[2], rangeCheck99[0]))
	constraint = c.qm31.Sub(constraint, memoryIdSums[2])
	constraint = c.qm31.Sub(constraint, rangeCheck99[0])
	constraint = c.qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	rangeIdx := 1
	partialIdx := 4
	for rangeIdx <= 26 {
		left := rangeCheck99[rangeIdx]
		right := rangeCheck99[rangeIdx+1]
		diff = c.qm31.Sub(partials[partialIdx], partials[partialIdx-1])
		constraint = c.qm31.Mul(diff, c.qm31.Mul(left, right))
		constraint = c.qm31.Sub(constraint, left)
		constraint = c.qm31.Sub(constraint, right)
		constraint = c.qm31.Mul(constraint, domainVanishInv)
		sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)
		rangeIdx += 2
		partialIdx++
	}

	diff = c.qm31.Sub(partials[partialIdx], partials[partialIdx-1])
	constraint = c.qm31.Mul(diff, c.qm31.Mul(rangeCheck99[27], rangeCheck19[0]))
	constraint = c.qm31.Sub(constraint, rangeCheck99[27])
	constraint = c.qm31.Sub(constraint, rangeCheck19[0])
	constraint = c.qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)
	partialIdx++

	range19Idx := 1
	for range19Idx <= 26 {
		left := rangeCheck19[range19Idx]
		right := rangeCheck19[range19Idx+1]
		diff = c.qm31.Sub(partials[partialIdx], partials[partialIdx-1])
		constraint = c.qm31.Mul(diff, c.qm31.Mul(left, right))
		constraint = c.qm31.Sub(constraint, left)
		constraint = c.qm31.Sub(constraint, right)
		constraint = c.qm31.Mul(constraint, domainVanishInv)
		sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)
		range19Idx += 2
		partialIdx++
	}

	diff = c.qm31.Sub(partials[partialIdx], partials[partialIdx-1])
	constraint = c.qm31.Mul(diff, c.qm31.Mul(rangeCheck19[27], opcodesSum63))
	constraint = c.qm31.Sub(constraint, c.qm31.Mul(rangeCheck19[27], enabler))
	constraint = c.qm31.Sub(constraint, opcodesSum63)
	constraint = c.qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	diff = c.qm31.Sub(partials[32], partials[31])
	diff = c.qm31.Sub(diff, prevPartial)
	diff = c.qm31.Add(diff, c.qm31.Mul(claimedSum, columnSizeInv))
	finalConstraint := c.qm31.Add(c.qm31.Mul(diff, opcodesSum64), enabler)
	finalConstraint = c.qm31.Mul(finalConstraint, domainVanishInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, finalConstraint)

	return sum
}
