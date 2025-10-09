package m31

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

const prime = uint64(PRIME)

// ╔══════════════════════════════════╗
// ║        Test Circuit Types        ║
// ╚══════════════════════════════════╝

// addCircuit wires two reduced additions through the chip.
type addCircuit struct {
	A        frontend.Variable
	B        frontend.Variable
	Expected frontend.Variable
}

func (c *addCircuit) Define(api frontend.API) error {
	chip := NewM31Chip(api)
	res := chip.Add(NewM31Unchecked(c.A), NewM31Unchecked(c.B))
	api.AssertIsEqual(res.x, c.Expected)
	return nil
}

// subCircuit wires a subtraction and checks the reduced output.
type subCircuit struct {
	A        frontend.Variable
	B        frontend.Variable
	Expected frontend.Variable
}

func (c *subCircuit) Define(api frontend.API) error {
	chip := NewM31Chip(api)
	res := chip.Sub(NewM31Unchecked(c.A), NewM31Unchecked(c.B))
	api.AssertIsEqual(res.x, c.Expected)
	return nil
}

// mulCircuit wires a multiplication and checks the reduced output.
type mulCircuit struct {
	A        frontend.Variable
	B        frontend.Variable
	Expected frontend.Variable
}

func (c *mulCircuit) Define(api frontend.API) error {
	chip := NewM31Chip(api)
	res := chip.Mul(NewM31Unchecked(c.A), NewM31Unchecked(c.B))
	api.AssertIsEqual(res.x, c.Expected)
	return nil
}

// mulAddCircuit wires an FMA and checks the reduced output.
type mulAddCircuit struct {
	A        frontend.Variable
	B        frontend.Variable
	C        frontend.Variable
	Expected frontend.Variable
}

func (c *mulAddCircuit) Define(api frontend.API) error {
	chip := NewM31Chip(api)
	res := chip.MulAdd(NewM31Unchecked(c.A), NewM31Unchecked(c.B), NewM31Unchecked(c.C))
	api.AssertIsEqual(res.x, c.Expected)
	return nil
}

// rangeCheckCircuit ensures RangeCheck accepts (or rejects) a witness.
type rangeCheckCircuit struct {
	Value frontend.Variable
}

func (c *rangeCheckCircuit) Define(api frontend.API) error {
	chip := NewM31Chip(api)
	chip.RangeCheck(NewM31Unchecked(c.Value))
	return nil
}

// inverseCircuit validates both the inverse value and zero flag.
type inverseCircuit struct {
	X              frontend.Variable
	ExpectedInv    frontend.Variable
	ExpectedHasInv frontend.Variable
}

func (c *inverseCircuit) Define(api frontend.API) error {
	chip := NewM31Chip(api)
	inv, hasInv := chip.Inverse(NewM31Unchecked(c.X))
	api.AssertIsEqual(inv.x, c.ExpectedInv)
	api.AssertIsEqual(hasInv, c.ExpectedHasInv)
	return nil
}

// smartAccSmallCircuit compares the smart accumulator with a naïve reduction flow.
type smartAccSmallCircuit struct {
	Adds  [3]frontend.Variable
	MulAs [2]frontend.Variable
	MulBs [2]frontend.Variable
}

func (c *smartAccSmallCircuit) Define(api frontend.API) error {
	chip := NewM31Chip(api)
	acc := chip.NewSmartAccumulator()
	naive := Zero()

	for _, add := range c.Adds {
		term := NewM31Unchecked(add)
		acc.Add(term)
		naive = chip.Add(naive, term)
	}

	for i := range c.MulAs {
		a := NewM31Unchecked(c.MulAs[i])
		b := NewM31Unchecked(c.MulBs[i])
		acc.MulAdd(a, b)
		product := chip.Mul(a, b)
		naive = chip.Add(naive, product)
	}

	accResult := acc.Finalize()
	api.AssertIsEqual(accResult.x, naive.x)
	return nil
}

// smartAccFlushCircuit forces multiple flushes within the smart accumulator.
type smartAccFlushCircuit struct {
	Adds  [2]frontend.Variable
	MulAs [10]frontend.Variable
	MulBs [10]frontend.Variable
}

func (c *smartAccFlushCircuit) Define(api frontend.API) error {
	chip := NewM31Chip(api)
	acc := chip.NewSmartAccumulator()
	naive := Zero()

	for _, add := range c.Adds {
		term := NewM31Unchecked(add)
		acc.Add(term)
		naive = chip.Add(naive, term)
	}

	for i := range c.MulAs {
		a := NewM31Unchecked(c.MulAs[i])
		b := NewM31Unchecked(c.MulBs[i])
		acc.MulAdd(a, b)
		product := chip.Mul(a, b)
		naive = chip.Add(naive, product)
	}

	accResult := acc.Finalize()
	api.AssertIsEqual(accResult.x, naive.x)
	return nil
}

// ╔══════════════════════════════════╗
// ║        Operation Test Cases      ║
// ╚══════════════════════════════════╝

func TestM31Add(t *testing.T) {
	testCases := []struct {
		name string
		a    uint64
		b    uint64
	}{
		{"both zero", 0, 0},
		{"simple", 1, 2},
		{"wrap to zero", prime - 1, 1},
		{"large operands", prime - 1, prime - 2},
	}

	assert := test.NewAssert(t)
	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			expected := modAdd(tc.a, tc.b)
			circuit := &addCircuit{}
			witness := &addCircuit{
				A:        tc.a,
				B:        tc.b,
				Expected: expected,
			}
			assert.ProverSucceeded(circuit, witness,
				test.WithCurves(ecc.BN254),
				test.WithBackends(backend.GROTH16),
				test.NoProverChecks(),
				test.NoFuzzing())
		})
	}
}

func TestM31Sub(t *testing.T) {
	testCases := []struct {
		name string
		a    uint64
		b    uint64
	}{
		{"equal operands", 1, 1},
		{"underflow wrap", 0, 1},
		{"large difference", 5, 7},
	}

	assert := test.NewAssert(t)
	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			expected := modSub(tc.a, tc.b)
			circuit := &subCircuit{}
			witness := &subCircuit{
				A:        tc.a,
				B:        tc.b,
				Expected: expected,
			}
			assert.ProverSucceeded(circuit, witness,
				test.WithCurves(ecc.BN254),
				test.WithBackends(backend.GROTH16),
				test.NoProverChecks(),
				test.NoFuzzing())
		})
	}
}

func TestM31Mul(t *testing.T) {
	testCases := []struct {
		name string
		a    uint64
		b    uint64
	}{
		{"zero multiplicand", 0, 12345},
		{"identity", 1, 987654},
		{"max elements", prime - 1, prime - 1},
		{"wrap case", 2, prime - 1},
	}

	assert := test.NewAssert(t)
	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			expected := modMul(tc.a, tc.b)
			circuit := &mulCircuit{}
			witness := &mulCircuit{
				A:        tc.a,
				B:        tc.b,
				Expected: expected,
			}
			assert.ProverSucceeded(circuit, witness,
				test.WithCurves(ecc.BN254),
				test.WithBackends(backend.GROTH16),
				test.NoProverChecks(),
				test.NoFuzzing())
		})
	}
}

func TestM31MulAdd(t *testing.T) {
	testCases := []struct {
		name string
		a    uint64
		b    uint64
		c    uint64
	}{
		{"all zero", 0, 0, 0},
		{"adds only", 0, 0, prime - 1},
		{"wrap from mul and add", prime - 1, prime - 1, 1},
		{"mixed operands", 123456, 789, 42},
	}

	assert := test.NewAssert(t)
	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			expected := modMulAdd(tc.a, tc.b, tc.c)
			circuit := &mulAddCircuit{}
			witness := &mulAddCircuit{
				A:        tc.a,
				B:        tc.b,
				C:        tc.c,
				Expected: expected,
			}
			assert.ProverSucceeded(circuit, witness,
				test.WithCurves(ecc.BN254),
				test.WithBackends(backend.GROTH16),
				test.NoProverChecks(),
				test.NoFuzzing())
		})
	}
}

func TestSmartAccumulatorSmall(t *testing.T) {
	assert := test.NewAssert(t)
	circuit := &smartAccSmallCircuit{}
	witness := &smartAccSmallCircuit{
		Adds:  [3]frontend.Variable{3, prime - 5, 42},
		MulAs: [2]frontend.Variable{7, prime - 9},
		MulBs: [2]frontend.Variable{11, 17},
	}

	assert.ProverSucceeded(circuit, witness,
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16),
		test.NoProverChecks(),
		test.NoFuzzing())
}

func TestSmartAccumulatorFlush(t *testing.T) {
	assert := test.NewAssert(t)
	circuit := &smartAccFlushCircuit{}
	witness := &smartAccFlushCircuit{
		Adds: [2]frontend.Variable{prime - 3, 99},
		MulAs: [10]frontend.Variable{
			prime - 2, prime - 4, prime - 6, prime - 8, prime - 10,
			prime - 12, prime - 14, prime - 16, prime - 18, prime - 20,
		},
		MulBs: [10]frontend.Variable{2, 3, 4, 5, 6, 7, 8, 9, 10, 11},
	}

	assert.ProverSucceeded(circuit, witness,
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16),
		test.NoProverChecks(),
		test.NoFuzzing())
}

// ╔══════════════════════════════════╗
// ║        Range Check Test Cases    ║
// ╚══════════════════════════════════╝

func TestM31RangeCheck(t *testing.T) {
	assert := test.NewAssert(t)

	validValues := []uint64{0, 1, 1<<16 - 1, prime - 1}
	for _, v := range validValues {
		v := v
		t.Run("valid_"+big.NewInt(int64(v)).String(), func(t *testing.T) {
			circuit := &rangeCheckCircuit{}
			witness := &rangeCheckCircuit{Value: v}
			assert.ProverSucceeded(circuit, witness,
				test.WithCurves(ecc.BN254),
				test.WithBackends(backend.GROTH16),
				test.NoProverChecks(),
				test.NoFuzzing())
		})
	}

	t.Run("invalid_equal_prime", func(t *testing.T) {
		circuit := &rangeCheckCircuit{}
		witness := &rangeCheckCircuit{Value: prime}
		assert.ProverFailed(circuit, witness,
			test.WithCurves(ecc.BN254),
			test.WithBackends(backend.GROTH16),
			test.NoProverChecks(),
			test.NoFuzzing())
	})
}

func TestM31Inverse(t *testing.T) {
	testCases := []struct {
		name           string
		x              uint64
		expectedHasInv uint64
	}{
		{"zero", 0, 0},
		{"one", 1, 1},
		{"random", 19, 1},
		{"prime_minus_two", prime - 2, 1},
	}

	assert := test.NewAssert(t)
	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			expectedInv := modInverse(tc.x)
			circuit := &inverseCircuit{}
			witness := &inverseCircuit{
				X:              tc.x,
				ExpectedInv:    expectedInv,
				ExpectedHasInv: tc.expectedHasInv,
			}
			assert.ProverSucceeded(circuit, witness,
				test.WithCurves(ecc.BN254),
				test.WithBackends(backend.GROTH16),
				test.NoProverChecks(),
				test.NoFuzzing())
		})
	}

	t.Run("inverse_fails_out_of_field", func(t *testing.T) {
		circuit := &inverseCircuit{}
		witness := &inverseCircuit{
			X:              prime,
			ExpectedInv:    0,
			ExpectedHasInv: 0,
		}
		assert.ProverFailed(circuit, witness,
			test.WithCurves(ecc.BN254),
			test.WithBackends(backend.GROTH16),
			test.NoProverChecks(),
			test.NoFuzzing())
	})
}

// ╔══════════════════════════════════╗
// ║        Helper Implementations    ║
// ╚══════════════════════════════════╝

func modAdd(a, b uint64) uint64 {
	sum := a + b
	if sum >= prime {
		sum -= prime
	}
	return sum
}

func modSub(a, b uint64) uint64 {
	if a >= b {
		return a - b
	}
	return prime - (b - a)
}

func modMul(a, b uint64) uint64 {
	return (a * b) % prime
}

func modMulAdd(a, b, c uint64) uint64 {
	return (modMul(a, b) + c) % prime
}

func modInverse(x uint64) uint64 {
	if x == 0 {
		return 0
	}
	exp := prime - 2
	base := big.NewInt(int64(x))
	mod := big.NewInt(int64(prime))
	result := new(big.Int).Exp(base, big.NewInt(int64(exp)), mod)
	return result.Uint64()
}
