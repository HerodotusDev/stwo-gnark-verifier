// Tests for cm31 operations come from :
// https://github.com/starkware-libs/stwo/blob/dev/crates/stwo/src/core/fields/cm31.rs

package m31

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

// ╔══════════════════════════════════╗
// ║          Test Circuits           ║
// ╚══════════════════════════════════╝

type cm31OpsCircuit struct{}

func (c *cm31OpsCircuit) Define(api frontend.API) error {
	m31Chip := NewM31Chip(api)
	cmChip := NewCM31Chip(m31Chip)

	cm0 := NewCM31(NewM31Unchecked(1), NewM31Unchecked(2))
	cm1 := NewCM31(NewM31Unchecked(4), NewM31Unchecked(5))
	m := NewM31Unchecked(8)
	cm := cmChip.CM31FromM31(m)
	cm0MulCm1 := cmChip.Mul(cm0, cm1)
	expectedMul := NewCM31(NewM31Unchecked(prime-6), NewM31Unchecked(13))
	assertEqualCM31(api, cm0MulCm1, expectedMul)

	sum := cmChip.Add(cm0, cm1)
	assertEqualCM31(api, sum, NewCM31(NewM31Unchecked(5), NewM31Unchecked(7)))

	sumWithM31 := cmChip.Add(cm1, cmChip.CM31FromM31(m))
	sumWithCM := cmChip.Add(cm1, cm)
	assertEqualCM31(api, sumWithM31, sumWithCM)

	prodWithM := cmChip.MulM31(cm1, m)
	prodWithCM := cmChip.Mul(cm1, cm)
	assertEqualCM31(api, prodWithM, prodWithCM)

	neg := cmChip.Neg(cm0)
	assertEqualCM31(api, neg, NewCM31(NewM31Unchecked(prime-1), NewM31Unchecked(prime-2)))

	diff := cmChip.Sub(cm0, cm1)
	assertEqualCM31(api, diff, NewCM31(NewM31Unchecked(prime-3), NewM31Unchecked(prime-3)))

	diffWithM31 := cmChip.Sub(cm1, cmChip.CM31FromM31(m))
	diffWithCM := cmChip.Sub(cm1, cm)
	assertEqualCM31(api, diffWithM31, diffWithCM)

	cm1Inverse := cmChip.Inverse(cm1)
	quotient := cmChip.Mul(cm0MulCm1, cm1Inverse)
	assertEqualCM31(api, quotient, cm0)

	mInverse, hasMinv := m31Chip.Inverse(m)
	api.AssertIsEqual(hasMinv, frontend.Variable(1))
	quotientWithM := cmChip.MulM31(cm1, mInverse)
	cmInverse := cmChip.Inverse(cm)
	quotientWithCM := cmChip.Mul(cm1, cmInverse)
	assertEqualCM31(api, quotientWithM, quotientWithCM)

	return nil
}

type cm31InverseCircuit struct {
	Value [2]frontend.Variable
}

func (c *cm31InverseCircuit) Define(api frontend.API) error {
	m31Chip := NewM31Chip(api)
	cmChip := NewCM31Chip(m31Chip)

	value := NewCM31(NewM31Unchecked(c.Value[0]), NewM31Unchecked(c.Value[1]))
	inverse := cmChip.Inverse(value)

	product := cmChip.Mul(value, inverse)
	one := cmChip.One()
	api.AssertIsEqual(product.A.x, one.A.x)
	api.AssertIsEqual(product.B.x, one.B.x)
	return nil
}

type cm31InverseSimpleCircuit struct{}

func (c *cm31InverseSimpleCircuit) Define(api frontend.API) error {
	m31Chip := NewM31Chip(api)
	cmChip := NewCM31Chip(m31Chip)

	cm := NewCM31(NewM31Unchecked(1), NewM31Unchecked(2))
	inverse := cmChip.Inverse(cm)
	product := cmChip.Mul(cm, inverse)
	assertEqualCM31(api, product, cmChip.One())
	return nil
}

// ╔══════════════════════════════════╗
// ║          Test Functions          ║
// ╚══════════════════════════════════╝

func TestCM31Ops(t *testing.T) {
	assert := test.NewAssert(t)
	circuit := &cm31OpsCircuit{}
	witness := &cm31OpsCircuit{}

	assert.ProverSucceeded(circuit, witness,
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16),
		test.NoProverChecks(),
		test.NoFuzzing())
}

func TestCM31Inverse(t *testing.T) {
	assert := test.NewAssert(t)
	circuit := &cm31InverseCircuit{}
	witness := &cm31InverseCircuit{Value: [2]frontend.Variable{3, 5}}

	assert.ProverSucceeded(circuit, witness,
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16),
		test.NoProverChecks(),
		test.NoFuzzing())

	badWitness := &cm31InverseCircuit{Value: [2]frontend.Variable{0, 0}}
	assert.ProverFailed(circuit, badWitness,
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16),
		test.NoProverChecks(),
		test.NoFuzzing())
}

func TestCM31InverseSimple(t *testing.T) {
	assert := test.NewAssert(t)
	circuit := &cm31InverseSimpleCircuit{}
	witness := &cm31InverseSimpleCircuit{}

	assert.ProverSucceeded(circuit, witness,
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16),
		test.NoProverChecks(),
		test.NoFuzzing())
}

// ╔══════════════════════════════════╗
// ║          Helper Functions        ║
// ╚══════════════════════════════════╝

func assertEqualCM31(api frontend.API, got, want CM31) {
	api.AssertIsEqual(got.A.x, want.A.x)
	api.AssertIsEqual(got.B.x, want.B.x)
}
