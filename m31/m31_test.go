package m31

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

// ╔══════════════════════════════════╗
// ║          Test Circuits           ║
// ╚══════════════════════════════════╝

type m31ArithmeticCircuit struct{}

func (c *m31ArithmeticCircuit) Define(api frontend.API) error {
	m31Chip := NewM31Chip(api)

	// Addition
	add := m31Chip.Add(NewM31Unchecked(1), NewM31Unchecked(3))
	m31Chip.AssertEqual(add, NewM31Unchecked(4))

	addWrap := m31Chip.Add(NewM31Unchecked(Prime-2), NewM31Unchecked(3))
	m31Chip.AssertEqual(addWrap, NewM31Unchecked(1))

	addUnchecked := m31Chip.AddUnchecked(NewM31Unchecked(Prime-2), NewM31Unchecked(3))
	addReduced := m31Chip.PartialReduce(addUnchecked)
	m31Chip.AssertEqual(addReduced, NewM31Unchecked(1))

	// Subtraction
	sub := m31Chip.Sub(NewM31Unchecked(7), NewM31Unchecked(3))
	m31Chip.AssertEqual(sub, NewM31Unchecked(4))

	subWrap := m31Chip.Sub(NewM31Unchecked(3), NewM31Unchecked(5))
	m31Chip.AssertEqual(subWrap, NewM31Unchecked(Prime-2))

	subUnchecked := m31Chip.SubUnchecked(NewM31Unchecked(3), NewM31Unchecked(5))
	subReduced := m31Chip.PartialReduce(subUnchecked)
	m31Chip.AssertEqual(subReduced, NewM31Unchecked(Prime-2))

	// Multiplication
	mul := m31Chip.Mul(NewM31Unchecked(3), NewM31Unchecked(5))
	m31Chip.AssertEqual(mul, NewM31Unchecked(15))

	mulWrap := m31Chip.Mul(NewM31Unchecked(Prime-1), NewM31Unchecked(Prime-1))
	m31Chip.AssertEqual(mulWrap, NewM31Unchecked(1))

	mulUnchecked := m31Chip.MulUnchecked(NewM31Unchecked(Prime-1), NewM31Unchecked(Prime-1))
	mulReduced := m31Chip.FullReduce(mulUnchecked)
	m31Chip.AssertEqual(mulReduced, NewM31Unchecked(1))

	// Division (implemented via inversion)
	checkDiv := func(num, denom, expected uint64) {
		numerator := NewM31Unchecked(num)
		denominator := NewM31Unchecked(denom)
		expectedVal := NewM31Unchecked(expected)

		inv, hasInv := m31Chip.Inverse(denominator)
		api.AssertIsEqual(hasInv, frontend.Variable(1))

		div := m31Chip.Mul(numerator, inv)
		m31Chip.AssertEqual(div, expectedVal)

		divUnchecked := m31Chip.MulUnchecked(numerator, inv)
		divReduced := m31Chip.FullReduce(divUnchecked)
		m31Chip.AssertEqual(divReduced, expectedVal)
	}

	checkDiv(8, 4, 2)
	checkDiv(3, PrimeU64-1, PrimeU64-3)

	return nil
}

type m31SmartAccumulatorCircuit struct{}

func (c *m31SmartAccumulatorCircuit) Define(api frontend.API) error {
	m31Chip := NewM31Chip(api)

	{
		acc := m31Chip.NewSmartAccumulator()
		expected := Zero()

		expr1 := NewM31Unchecked(5)
		acc.AddExpression(expr1, 0)
		expected = m31Chip.Add(expected, expr1)

		a := NewM31Unchecked(97)
		b := NewM31Unchecked(33)
		d1 := NewM31Unchecked(201)
		d2 := NewM31Unchecked(17)
		expr2 := m31Chip.MulUnchecked(m31Chip.MulUnchecked(m31Chip.SubUnchecked(a, b), d1), d2)
		acc.AddExpression(expr2, productBitCost(3)+quotientBitsPerAdd)
		expr2Reduced := m31Chip.Mul(m31Chip.Mul(m31Chip.Sub(a, b), d1), d2)
		expected = m31Chip.Add(expected, expr2Reduced)

		accResult := acc.Finalize()
		api.AssertIsEqual(accResult.Limb, expected.Limb)
	}

	{
		acc := m31Chip.NewSmartAccumulator()
		expected := Zero()

		expr := NewM31Unchecked(7)
		acc.AddExpression(expr, uint64(maxQuotientBits-1))
		expected = m31Chip.Add(expected, expr)

		prod := m31Chip.MulUnchecked(NewM31Unchecked(71), NewM31Unchecked(Prime-91))
		acc.AddExpression(prod, productBitCost(2))
		prodReduced := m31Chip.Mul(NewM31Unchecked(71), NewM31Unchecked(Prime-91))
		expected = m31Chip.Add(expected, prodReduced)

		acc.MulExpression(NewM31Unchecked(19), 32)
		expected = m31Chip.Mul(expected, NewM31Unchecked(19))

		accResult := acc.Finalize()
		api.AssertIsEqual(accResult.Limb, expected.Limb)
	}

	return nil
}

type batchInverseFailureCircuit struct{}

func (c *batchInverseFailureCircuit) Define(api frontend.API) error {
	m31Chip := NewM31Chip(api)
	values := []M31{NewM31Unchecked(0), NewM31Unchecked(5)}
	m31Chip.BatchInverse(values)
	return nil
}

// ╔══════════════════════════════════╗
// ║          Test Functions          ║
// ╚══════════════════════════════════╝

func TestM31Arithmetic(t *testing.T) {
	assert := test.NewAssert(t)
	circuit := &m31ArithmeticCircuit{}
	witness := &m31ArithmeticCircuit{}

	assert.CheckCircuit(circuit,
		test.WithValidAssignment(witness),
		test.WithCurves(ecc.BN254),
	)
}

func TestM31SmartAccumulator(t *testing.T) {
	assert := test.NewAssert(t)
	circuit := &m31SmartAccumulatorCircuit{}
	witness := &m31SmartAccumulatorCircuit{}

	assert.CheckCircuit(circuit,
		test.WithValidAssignment(witness),
		test.WithCurves(ecc.BN254),
	)
}

func TestBatchInverseFailure(t *testing.T) {
	assert := test.NewAssert(t)
	circuit := &batchInverseFailureCircuit{}
	witness := &batchInverseFailureCircuit{}

	assert.CheckCircuit(circuit,
		test.WithInvalidAssignment(witness),
		test.WithCurves(ecc.BN254),
	)
}
