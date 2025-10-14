package components

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/HerodotusDev/stwo-gnark-verifier/variables"
	"github.com/consensys/gnark/frontend"
)

type MemoryAddressToIdComponent struct {
	api  frontend.API
	qm31 *m31.QM31Chip

	interactionElements m31.InteractionElements
	columnSize          uint32
	claimedSum          m31.QM31
	vanishEvalInv       m31.QM31

	N_COLUMNS             uint32
	N_INTERACTION_COLUMNS uint32
}

func NewMemoryAddressToId(api frontend.API, qm31 *m31.QM31Chip, interactionElements m31.InteractionElements, logSize uint32, claimedSum m31.QM31, oodsPoint m31.QM31) *MemoryAddressToIdComponent {
	// TODO: Compute vanishEval from the oods point and logSize
	vanishEvalInv := qm31.Inverse(qm31.One())

	return &MemoryAddressToIdComponent{
		api:                   api,
		qm31:                  qm31,
		interactionElements:   interactionElements,
		columnSize:            1 << logSize,
		claimedSum:            claimedSum,
		vanishEvalInv:         vanishEvalInv,
		N_COLUMNS:             16,
		N_INTERACTION_COLUMNS: 16,
	}
}

func (c *MemoryAddressToIdComponent) Evaluate(sum m31.QM31, sampledValues [][][]m31.QM31, random_coeff m31.QM31) m31.QM31 {
	// TODO: Handle preprocessed trace (the +1 is because addresses start at 1)
	seq := c.qm31.Add(c.qm31.One(), c.qm31.One())

	// we assume that the sampled values starts with the memory_address_to_id component (the previous columns were popped)
	id_0 := sampledValues[variables.MAIN_IDX][0][0]
	mult_0 := sampledValues[variables.MAIN_IDX][1][0]
	id_1 := sampledValues[variables.MAIN_IDX][2][0]
	mult_1 := sampledValues[variables.MAIN_IDX][3][0]
	id_2 := sampledValues[variables.MAIN_IDX][4][0]
	mult_2 := sampledValues[variables.MAIN_IDX][5][0]
	id_3 := sampledValues[variables.MAIN_IDX][6][0]
	mult_3 := sampledValues[variables.MAIN_IDX][7][0]
	id_4 := sampledValues[variables.MAIN_IDX][8][0]
	mult_4 := sampledValues[variables.MAIN_IDX][9][0]
	id_5 := sampledValues[variables.MAIN_IDX][10][0]
	mult_5 := sampledValues[variables.MAIN_IDX][11][0]
	id_6 := sampledValues[variables.MAIN_IDX][12][0]
	mult_6 := sampledValues[variables.MAIN_IDX][13][0]
	id_7 := sampledValues[variables.MAIN_IDX][14][0]
	mult_7 := sampledValues[variables.MAIN_IDX][15][0]

	interaction_column_0 := sampledValues[variables.INTERACTION_IDX][0][0]
	interaction_column_1 := sampledValues[variables.INTERACTION_IDX][1][0]
	interaction_column_2 := sampledValues[variables.INTERACTION_IDX][2][0]
	interaction_column_3 := sampledValues[variables.INTERACTION_IDX][3][0]
	interaction_column_4 := sampledValues[variables.INTERACTION_IDX][4][0]
	interaction_column_5 := sampledValues[variables.INTERACTION_IDX][5][0]
	interaction_column_6 := sampledValues[variables.INTERACTION_IDX][6][0]
	interaction_column_7 := sampledValues[variables.INTERACTION_IDX][7][0]
	interaction_column_8 := sampledValues[variables.INTERACTION_IDX][8][0]
	interaction_column_9 := sampledValues[variables.INTERACTION_IDX][9][0]
	interaction_column_10 := sampledValues[variables.INTERACTION_IDX][10][0]
	interaction_column_11 := sampledValues[variables.INTERACTION_IDX][11][0]
	interaction_column_12 := sampledValues[variables.INTERACTION_IDX][12][0]
	interaction_column_12_neg1 := sampledValues[variables.INTERACTION_IDX][12][1]
	interaction_column_13 := sampledValues[variables.INTERACTION_IDX][13][0]
	interaction_column_13_neg1 := sampledValues[variables.INTERACTION_IDX][13][1]
	interaction_column_14 := sampledValues[variables.INTERACTION_IDX][14][0]
	interaction_column_14_neg1 := sampledValues[variables.INTERACTION_IDX][14][1]
	interaction_column_15 := sampledValues[variables.INTERACTION_IDX][15][0]
	interaction_column_15_neg1 := sampledValues[variables.INTERACTION_IDX][15][1]

	// Computation of combined values
	columnSizeQM31 := c.qm31.FromM31(m31.NewM31Unchecked(c.columnSize))
	oneQM31 := c.qm31.FromM31(m31.One())

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
		c.qm31.Mul(c.claimedSum, c.qm31.Inverse(c.qm31.FromM31(m31.NewM31Unchecked(c.columnSize)))),
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
