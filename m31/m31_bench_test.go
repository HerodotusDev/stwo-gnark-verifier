package m31

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
)

const (
	benchAddCount    = 4
	benchMulAddCount = 16
)

// naiveAccumulatorCircuit reduces after every operation using the standard chip API.
type naiveAccumulatorCircuit struct {
	Adds  [benchAddCount]frontend.Variable
	MulAs [benchMulAddCount]frontend.Variable
	MulBs [benchMulAddCount]frontend.Variable
}

func (c *naiveAccumulatorCircuit) Define(api frontend.API) error {
	chip := NewM31Chip(api)
	acc := Zero()

	for _, add := range c.Adds {
		term := NewM31Unchecked(add)
		acc = chip.Add(acc, term)
	}
	for i := range c.MulAs {
		a := NewM31Unchecked(c.MulAs[i])
		b := NewM31Unchecked(c.MulBs[i])
		acc = chip.MulAdd(a, b, acc)
	}

	// Keep the compiler from dropping the result.
	api.AssertIsEqual(acc.Limb, acc.Limb)
	return nil
}

// smartAccumulatorCircuit batches operations and reduces only when required.
type smartAccumulatorCircuit struct {
	Adds  [benchAddCount]frontend.Variable
	MulAs [benchMulAddCount]frontend.Variable
	MulBs [benchMulAddCount]frontend.Variable
}

func (c *smartAccumulatorCircuit) Define(api frontend.API) error {
	chip := NewM31Chip(api)
	acc := chip.NewSmartAccumulator()

	for _, add := range c.Adds {
		acc.AddExpression(NewM31Unchecked(add), quotientBitsPerAdd)
	}
	for i := range c.MulAs {
		a := NewM31Unchecked(c.MulAs[i])
		b := NewM31Unchecked(c.MulBs[i])
		prod := chip.MulUnchecked(a, b)
		acc.AddExpression(prod, productBitCost(2))
	}

	result := acc.Finalize()
	api.AssertIsEqual(result.Limb, result.Limb)
	return nil
}

func compileConstraintCount(b *testing.B, circuit frontend.Circuit) uint64 {
	b.Helper()
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, circuit)
	if err != nil {
		b.Fatalf("compile circuit: %v", err)
	}
	return uint64(cs.GetNbConstraints())
}

func BenchmarkAccumulatorConstraintCounts(b *testing.B) {
	addInputs := [benchAddCount]frontend.Variable{3, 5, PRIME - 7, 91}
	var mulAInputs [benchMulAddCount]frontend.Variable
	var mulBInputs [benchMulAddCount]frontend.Variable

	for i := 0; i < benchMulAddCount; i++ {
		mulAInputs[i] = frontend.Variable(PRIME - uint32(2*i+3))
		mulBInputs[i] = frontend.Variable(i + 2)
	}

	naiveCircuit := &naiveAccumulatorCircuit{
		Adds:  addInputs,
		MulAs: mulAInputs,
		MulBs: mulBInputs,
	}
	smartCircuit := &smartAccumulatorCircuit{
		Adds:  addInputs,
		MulAs: mulAInputs,
		MulBs: mulBInputs,
	}

	for i := 0; i < b.N; i++ {
		naiveConstraints := compileConstraintCount(b, naiveCircuit)
		smartConstraints := compileConstraintCount(b, smartCircuit)

		b.ReportMetric(float64(naiveConstraints), "constraints_naive")
		b.ReportMetric(float64(smartConstraints), "constraints_smart")
		if smartConstraints > 0 {
			b.ReportMetric(float64(naiveConstraints)/float64(smartConstraints), "ratio_naive_to_smart")
		}
	}
}
