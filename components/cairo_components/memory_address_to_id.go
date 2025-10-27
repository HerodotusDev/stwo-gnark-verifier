package cairo_components

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
	gnarkbits "github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/uints"
)

// MemoryAddressToIdClaim carries the circuit-facing claim for the component.
type MemoryAddressToIdClaim struct {
	LogSize uints.U8
}

// MemoryAddressToIdInteractionClaim carries the interaction claim data.
type MemoryAddressToIdInteractionClaim struct {
	ClaimedSum m31.QM31
}

// MemoryAddressToIdComponent embeds the constraints for the memory_address_to_id table.
type MemoryAddressToIdComponent struct {
	api  frontend.API
	qm31 *m31.QM31Chip

	interactionElements m31.InteractionElements
	logSize             uints.U8
	columnSize          frontend.Variable
	claimedSum          m31.QM31
	vanishEvalInv       m31.QM31

	N_COLUMNS             uint32
	N_INTERACTION_COLUMNS uint32
}

// NewMemoryAddressToId wires the component constraints into the circuit.
func NewMemoryAddressToId(
	api frontend.API,
	qm31 *m31.QM31Chip,
	interactionElements m31.InteractionElements,
	claim MemoryAddressToIdClaim,
	interactionClaim MemoryAddressToIdInteractionClaim,
	oodsPoint m31.QM31,
) *MemoryAddressToIdComponent {
	bytesAPI, err := uints.NewBytes(api)
	if err != nil {
		panic(err)
	}

	logSizeValue := bytesAPI.Value(claim.LogSize)
	logSizeBits := gnarkbits.ToBinary(api, logSizeValue, gnarkbits.WithNbDigits(8))

	columnSize := frontend.Variable(1)
	for i := len(logSizeBits) - 1; i >= 0; i-- {
		if i != len(logSizeBits)-1 {
			columnSize = api.Mul(columnSize, columnSize)
		}
		candidate := api.Mul(columnSize, 2)
		columnSize = api.Select(logSizeBits[i], candidate, columnSize)
	}

	// TODO: Compute vanishEval from the oods point and logSize
	vanishEvalInv := qm31.Inverse(qm31.One())

	return &MemoryAddressToIdComponent{
		api:                   api,
		qm31:                  qm31,
		interactionElements:   interactionElements,
		logSize:               claim.LogSize,
		columnSize:            columnSize,
		claimedSum:            interactionClaim.ClaimedSum,
		vanishEvalInv:         vanishEvalInv,
		N_COLUMNS:             16,
		N_INTERACTION_COLUMNS: 16,
	}
}

// Evaluate enforces the component constraints at the sampled point.
func (c *MemoryAddressToIdComponent) Evaluate(sum m31.QM31, preprocessedSampledValues PreprocessedSampledValues, traceSampledValues [][]m31.QM31, interactionSampledValues [][]m31.QM31, random_coeff m31.QM31) m31.QM31 {
	// Addresses start at 1 in the trace, so shift by one after reading the sequence column.
	seq := preprocessedSampledValues.Get(NewPreprocessedColumnSeq(c.logSize))

	// we assume that the sampled values starts with the memory_address_to_id component (the previous columns were popped)
	id_0 := traceSampledValues[0][0]
	mult_0 := traceSampledValues[1][0]
	id_1 := traceSampledValues[2][0]
	mult_1 := traceSampledValues[3][0]
	id_2 := traceSampledValues[4][0]
	mult_2 := traceSampledValues[5][0]
	id_3 := traceSampledValues[6][0]
	mult_3 := traceSampledValues[7][0]
	id_4 := traceSampledValues[8][0]
	mult_4 := traceSampledValues[9][0]
	id_5 := traceSampledValues[10][0]
	mult_5 := traceSampledValues[11][0]
	id_6 := traceSampledValues[12][0]
	mult_6 := traceSampledValues[13][0]
	id_7 := traceSampledValues[14][0]
	mult_7 := traceSampledValues[15][0]

	interaction_column_0 := interactionSampledValues[0][0]
	interaction_column_1 := interactionSampledValues[1][0]
	interaction_column_2 := interactionSampledValues[2][0]
	interaction_column_3 := interactionSampledValues[3][0]
	interaction_column_4 := interactionSampledValues[4][0]
	interaction_column_5 := interactionSampledValues[5][0]
	interaction_column_6 := interactionSampledValues[6][0]
	interaction_column_7 := interactionSampledValues[7][0]
	interaction_column_8 := interactionSampledValues[8][0]
	interaction_column_9 := interactionSampledValues[9][0]
	interaction_column_10 := interactionSampledValues[10][0]
	interaction_column_11 := interactionSampledValues[11][0]
	interaction_column_12 := interactionSampledValues[12][0]
	interaction_column_12_neg1 := interactionSampledValues[12][1]
	interaction_column_13 := interactionSampledValues[13][0]
	interaction_column_13_neg1 := interactionSampledValues[13][1]
	interaction_column_14 := interactionSampledValues[14][0]
	interaction_column_14_neg1 := interactionSampledValues[14][1]
	interaction_column_15 := interactionSampledValues[15][0]
	interaction_column_15_neg1 := interactionSampledValues[15][1]

	// Computation of combined values
	columnSizeQM31 := m31.NewQM31FromM31(m31.NewM31Unchecked(c.columnSize))
	oneQM31 := m31.NewQM31FromM31(m31.One())

	addr := c.qm31.Add(seq, oneQM31)
	combine_0, err := c.qm31.Combine(c.interactionElements, []m31.QM31{addr, id_0})
	if err != nil {
		panic(err)
	}

	addr = c.qm31.Add(addr, columnSizeQM31)
	combine_1, err := c.qm31.Combine(c.interactionElements, []m31.QM31{addr, id_1})
	if err != nil {
		panic(err)
	}

	addr = c.qm31.Add(addr, columnSizeQM31)
	combine_2, err := c.qm31.Combine(c.interactionElements, []m31.QM31{addr, id_2})
	if err != nil {
		panic(err)
	}

	addr = c.qm31.Add(addr, columnSizeQM31)
	combine_3, err := c.qm31.Combine(c.interactionElements, []m31.QM31{addr, id_3})
	if err != nil {
		panic(err)
	}

	addr = c.qm31.Add(addr, columnSizeQM31)
	combine_4, err := c.qm31.Combine(c.interactionElements, []m31.QM31{addr, id_4})
	if err != nil {
		panic(err)
	}

	addr = c.qm31.Add(addr, columnSizeQM31)
	combine_5, err := c.qm31.Combine(c.interactionElements, []m31.QM31{addr, id_5})
	if err != nil {
		panic(err)
	}

	addr = c.qm31.Add(addr, columnSizeQM31)
	combine_6, err := c.qm31.Combine(c.interactionElements, []m31.QM31{addr, id_6})
	if err != nil {
		panic(err)
	}

	addr = c.qm31.Add(addr, columnSizeQM31)
	combine_7, err := c.qm31.Combine(c.interactionElements, []m31.QM31{addr, id_7})
	if err != nil {
		panic(err)
	}

	// Computation of diffs (curr_sum - prev_sum)
	diff_0 := c.qm31.FromPartialEvals(interaction_column_0, interaction_column_1, interaction_column_2, interaction_column_3)
	diff_1 := c.qm31.Sub(
		c.qm31.FromPartialEvals(interaction_column_4, interaction_column_5, interaction_column_6, interaction_column_7),
		c.qm31.FromPartialEvals(interaction_column_0, interaction_column_1, interaction_column_2, interaction_column_3),
	)
	diff_2 := c.qm31.Sub(
		c.qm31.FromPartialEvals(interaction_column_8, interaction_column_9, interaction_column_10, interaction_column_11),
		c.qm31.FromPartialEvals(interaction_column_4, interaction_column_5, interaction_column_6, interaction_column_7),
	)
	diff_3 := c.qm31.Add(
		c.qm31.Sub(
			c.qm31.Sub(
				c.qm31.FromPartialEvals(interaction_column_12, interaction_column_13, interaction_column_14, interaction_column_15),
				c.qm31.FromPartialEvals(interaction_column_12_neg1, interaction_column_13_neg1, interaction_column_14_neg1, interaction_column_15_neg1),
			),
			c.qm31.FromPartialEvals(interaction_column_8, interaction_column_9, interaction_column_10, interaction_column_11),
		),
		c.qm31.Mul(c.claimedSum, c.qm31.Inverse(m31.NewQM31FromM31(m31.NewM31Unchecked(c.columnSize)))),
	)

	// Evaluation (diff * denom - num = 0)
	// Constraint 0
	denom_0 := c.qm31.Mul(combine_0, combine_1)
	num_0 := c.qm31.Add(
		c.qm31.Mul(combine_1, mult_0),
		c.qm31.Mul(combine_0, mult_1),
	)
	constraint_0 := c.qm31.Add(c.qm31.Mul(diff_0, denom_0), num_0)
	sum = c.qm31.Add(
		c.qm31.Mul(sum, random_coeff),
		c.qm31.Mul(constraint_0, c.vanishEvalInv),
	)

	// Constraint 1
	denom_1 := c.qm31.Mul(combine_2, combine_3)
	num_1 := c.qm31.Add(
		c.qm31.Mul(combine_3, mult_2),
		c.qm31.Mul(combine_2, mult_3),
	)
	constraint_1 := c.qm31.Add(c.qm31.Mul(diff_1, denom_1), num_1)
	sum = c.qm31.Add(
		c.qm31.Mul(sum, random_coeff),
		c.qm31.Mul(constraint_1, c.vanishEvalInv),
	)

	// Constraint 2
	denom_2 := c.qm31.Mul(combine_4, combine_5)
	num_2 := c.qm31.Add(
		c.qm31.Mul(combine_5, mult_4),
		c.qm31.Mul(combine_4, mult_5),
	)
	constraint_2 := c.qm31.Add(c.qm31.Mul(diff_2, denom_2), num_2)
	sum = c.qm31.Add(
		c.qm31.Mul(sum, random_coeff),
		c.qm31.Mul(constraint_2, c.vanishEvalInv),
	)

	// Constraint 3
	denom_3 := c.qm31.Mul(combine_6, combine_7)
	num_3 := c.qm31.Add(
		c.qm31.Mul(combine_7, mult_6),
		c.qm31.Mul(combine_6, mult_7),
	)
	constraint_3 := c.qm31.Add(c.qm31.Mul(diff_3, denom_3), num_3)
	sum = c.qm31.Add(
		c.qm31.Mul(sum, random_coeff),
		c.qm31.Mul(constraint_3, c.vanishEvalInv),
	)

	return sum
}
