package cairo_components

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
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
	columnSize          m31.QM31
	claimedSum          m31.QM31
	vanishEvalInv       m31.QM31

	N_COLUMNS             int
	N_INTERACTION_COLUMNS int
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
	// Compute the column size inside the circuit using our shared helper
	columnSize := computeColumnSize(api, claim.LogSize)

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
func (c *MemoryAddressToIdComponent) Evaluate(sum m31.QM31, traces *Traces, random_coeff m31.QM31) m31.QM31 {
	traceSampledValues, interactionSampledValues := traces.Take(c.N_COLUMNS, c.N_INTERACTION_COLUMNS)

	// ╔══════════════════════════════════╗
	// ║        Preprocessed Trace        ║
	// ╚══════════════════════════════════╝
	// Addresses start at 1 in the trace, so shift by one after reading the sequence column.
	seq := traces.Get(NewPreprocessedColumnSeq(c.logSize))

	// ╔══════════════════════════════════╗
	// ║            Main Trace            ║
	// ╚══════════════════════════════════╝
	id_0 := traceSampledValues.Get(0)
	mult_0 := traceSampledValues.Get(1)
	id_1 := traceSampledValues.Get(2)
	mult_1 := traceSampledValues.Get(3)
	id_2 := traceSampledValues.Get(4)
	mult_2 := traceSampledValues.Get(5)
	id_3 := traceSampledValues.Get(6)
	mult_3 := traceSampledValues.Get(7)
	id_4 := traceSampledValues.Get(8)
	mult_4 := traceSampledValues.Get(9)
	id_5 := traceSampledValues.Get(10)
	mult_5 := traceSampledValues.Get(11)
	id_6 := traceSampledValues.Get(12)
	mult_6 := traceSampledValues.Get(13)
	id_7 := traceSampledValues.Get(14)
	mult_7 := traceSampledValues.Get(15)

	// ╔══════════════════════════════════╗
	// ║         Interaction Trace        ║
	// ╚══════════════════════════════════╝
	part0 := interactionSampledValues.Partial(c.qm31, 0, 0)
	part1 := interactionSampledValues.Partial(c.qm31, 4, 0)
	part2 := interactionSampledValues.Partial(c.qm31, 8, 0)
	part3Prev := interactionSampledValues.Partial(c.qm31, 12, 0)
	part3 := interactionSampledValues.Partial(c.qm31, 12, 1)

	// ╔══════════════════════════════════╗
	// ║       Constraint Evaluations     ║
	// ╚══════════════════════════════════╝

	columnSizeQM31 := c.columnSize
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
	diff_0 := part0
	diff_1 := c.qm31.Sub(part1, part0)
	diff_2 := c.qm31.Sub(part2, part1)
	diff_3 := c.qm31.Add(
		c.qm31.Sub(
			c.qm31.Sub(part3, part3Prev),
			part2,
		),
		c.qm31.Mul(c.claimedSum, c.qm31.Inverse(c.columnSize)),
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
