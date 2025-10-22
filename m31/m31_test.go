package m31

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

const prime = uint64(PRIME)

// ╔══════════════════════════════════╗
// ║          Test Circuits           ║
// ╚══════════════════════════════════╝

type m31ArithmeticCircuit struct{}

func (c *m31ArithmeticCircuit) Define(api frontend.API) error {
	chip := NewM31Chip(api)

	// Addition
	add := chip.Add(NewM31Unchecked(1), NewM31Unchecked(3))
	assertEqualM31(api, add, NewM31Unchecked(4))

	addWrap := chip.Add(NewM31Unchecked(prime-2), NewM31Unchecked(3))
	assertEqualM31(api, addWrap, NewM31Unchecked(1))

	addUnchecked := chip.AddUnchecked(NewM31Unchecked(prime-2), NewM31Unchecked(3))
	addReduced := chip.PartialReduce(addUnchecked)
	assertEqualM31(api, addReduced, NewM31Unchecked(1))

	// Subtraction
	sub := chip.Sub(NewM31Unchecked(7), NewM31Unchecked(3))
	assertEqualM31(api, sub, NewM31Unchecked(4))

	subWrap := chip.Sub(NewM31Unchecked(3), NewM31Unchecked(5))
	assertEqualM31(api, subWrap, NewM31Unchecked(prime-2))

	subUnchecked := chip.SubUnchecked(NewM31Unchecked(3), NewM31Unchecked(5))
	subReduced := chip.PartialReduce(subUnchecked)
	assertEqualM31(api, subReduced, NewM31Unchecked(prime-2))

	// Multiplication
	mul := chip.Mul(NewM31Unchecked(3), NewM31Unchecked(5))
	assertEqualM31(api, mul, NewM31Unchecked(15))

	mulWrap := chip.Mul(NewM31Unchecked(prime-1), NewM31Unchecked(prime-1))
	assertEqualM31(api, mulWrap, NewM31Unchecked(1))

	mulUnchecked := chip.MulUnchecked(NewM31Unchecked(prime-1), NewM31Unchecked(prime-1))
	mulReduced := chip.FullReduce(mulUnchecked)
	assertEqualM31(api, mulReduced, NewM31Unchecked(1))

	// Division (implemented via inversion)
	checkDiv := func(num, denom, expected uint64) {
		numerator := NewM31Unchecked(num)
		denominator := NewM31Unchecked(denom)
		expectedVal := NewM31Unchecked(expected)

		inv, hasInv := chip.Inverse(denominator)
		api.AssertIsEqual(hasInv, frontend.Variable(1))

		div := chip.Mul(numerator, inv)
		assertEqualM31(api, div, expectedVal)

		divUnchecked := chip.MulUnchecked(numerator, inv)
		divReduced := chip.FullReduce(divUnchecked)
		assertEqualM31(api, divReduced, expectedVal)
	}

	checkDiv(8, 4, 2)
	checkDiv(3, prime-1, prime-3)

	return nil
}

type m31SmartAccumulatorCircuit struct{}

func (c *m31SmartAccumulatorCircuit) Define(api frontend.API) error {
	chip := NewM31Chip(api)

	{
		acc := chip.NewSmartAccumulator()
		expected := Zero()

		expr1 := NewM31Unchecked(5)
		acc.AddExpression(expr1, 0)
		expected = chip.Add(expected, expr1)

		a := NewM31Unchecked(97)
		b := NewM31Unchecked(33)
		d1 := NewM31Unchecked(201)
		d2 := NewM31Unchecked(17)
		expr2 := chip.MulUnchecked(chip.MulUnchecked(chip.SubUnchecked(a, b), d1), d2)
		acc.AddExpression(expr2, productBitCost(3)+quotientBitsPerAdd)
		expr2Reduced := chip.Mul(chip.Mul(chip.Sub(a, b), d1), d2)
		expected = chip.Add(expected, expr2Reduced)

		accResult := acc.Finalize()
		api.AssertIsEqual(accResult.Limb, expected.Limb)
	}

	{
		acc := chip.NewSmartAccumulator()
		expected := Zero()

		expr := NewM31Unchecked(7)
		acc.AddExpression(expr, uint64(maxQuotientBits-1))
		expected = chip.Add(expected, expr)

		prod := chip.MulUnchecked(NewM31Unchecked(71), NewM31Unchecked(prime-91))
		acc.AddExpression(prod, productBitCost(2))
		prodReduced := chip.Mul(NewM31Unchecked(71), NewM31Unchecked(prime-91))
		expected = chip.Add(expected, prodReduced)

		acc.MulExpression(NewM31Unchecked(19), 32)
		expected = chip.Mul(expected, NewM31Unchecked(19))

		accResult := acc.Finalize()
		api.AssertIsEqual(accResult.Limb, expected.Limb)
	}

	return nil
}

type batchInverseFailureCircuit struct{}

func (c *batchInverseFailureCircuit) Define(api frontend.API) error {
	chip := NewM31Chip(api)
	values := []M31{NewM31Unchecked(0), NewM31Unchecked(5)}
	chip.BatchInverse(values)
	return nil
}

// ╔══════════════════════════════════╗
// ║          Test Functions          ║
// ╚══════════════════════════════════╝

func TestM31Arithmetic(t *testing.T) {
	assert := test.NewAssert(t)
	circuit := &m31ArithmeticCircuit{}
	witness := &m31ArithmeticCircuit{}

	assert.ProverSucceeded(circuit, witness,
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16),
		test.NoProverChecks(),
		test.NoFuzzing())
}

func TestM31SmartAccumulator(t *testing.T) {
	assert := test.NewAssert(t)
	circuit := &m31SmartAccumulatorCircuit{}
	witness := &m31SmartAccumulatorCircuit{}

	assert.ProverSucceeded(circuit, witness,
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16),
		test.NoProverChecks(),
		test.NoFuzzing())
}

func TestBatchInverseFailure(t *testing.T) {
	assert := test.NewAssert(t)
	circuit := &batchInverseFailureCircuit{}
	witness := &batchInverseFailureCircuit{}

	assert.ProverFailed(circuit, witness,
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16),
		test.NoProverChecks(),
		test.NoFuzzing())
}

// ╔══════════════════════════════════╗
// ║          Helper Functions        ║
// ╚══════════════════════════════════╝

func assertEqualM31(api frontend.API, got, want M31) {
	api.AssertIsEqual(got.Limb, want.Limb)
}

func productBitCost(factors int) uint64 {
	if factors <= 1 {
		return quotientBitsPerAdd
	}
	return validateBudget(uint64(factors-1)*31 + quotientBitsPerAdd)
}
