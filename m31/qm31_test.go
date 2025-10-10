// Tests for qm31 operations come from :
// https://github.com/starkware-libs/stwo/blob/dev/crates/stwo/src/core/fields/qm31.rs

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

type qm31OpsCircuit struct{}

func (c *qm31OpsCircuit) Define(api frontend.API) error {
	m31Chip := NewM31Chip(api)
	cmChip := NewCM31Chip(m31Chip)
	qmChip := NewQM31Chip(cmChip)

	newCM := func(a, b uint64) CM31 {
		return NewCM31(NewM31Unchecked(a), NewM31Unchecked(b))
	}

	qm0 := QM31{A: newCM(1, 2), B: newCM(3, 4)}
	qm1 := QM31{A: newCM(4, 5), B: newCM(6, 7)}
	m := NewM31Unchecked(8)
	qm := qmChip.FromM31(m)
	qm0xqm1 := QM31{
		A: newCM(prime-71, 93),
		B: newCM(prime-16, 50),
	}

	sum := qmChip.Add(qm0, qm1)
	assertEqualQM31(api, sum, QM31{
		A: newCM(5, 7),
		B: newCM(9, 11),
	})

	sumWithM31 := qmChip.Add(qm1, qmChip.FromM31(m))
	sumWithQM := qmChip.Add(qm1, qm)
	assertEqualQM31(api, sumWithM31, sumWithQM)

	product := qmChip.Mul(qm0, qm1)
	assertEqualQM31(api, product, qm0xqm1)

	prodWithM := qmChip.MulM31(qm1, m)
	prodWithQM := qmChip.Mul(qm1, qm)
	assertEqualQM31(api, prodWithM, prodWithQM)

	neg := qmChip.Neg(qm0)
	assertEqualQM31(api, neg, QM31{
		A: newCM(prime-1, prime-2),
		B: newCM(prime-3, prime-4),
	})

	diff := qmChip.Sub(qm0, qm1)
	assertEqualQM31(api, diff, QM31{
		A: newCM(prime-3, prime-3),
		B: newCM(prime-3, prime-3),
	})

	diffWithM31 := qmChip.Sub(qm1, qmChip.FromM31(m))
	diffWithQM := qmChip.Sub(qm1, qm)
	assertEqualQM31(api, diffWithM31, diffWithQM)

	qm1Inverse := qmChip.Inverse(qm1)
	quotient := qmChip.Mul(qm0xqm1, qm1Inverse)
	assertEqualQM31(api, quotient, qm0)

	mInverse, hasMinv := m31Chip.Inverse(m)
	api.AssertIsEqual(hasMinv, frontend.Variable(1))
	quotientWithM := qmChip.MulM31(qm1, mInverse)
	qmInverse := qmChip.Inverse(qm)
	quotientWithQM := qmChip.Mul(qm1, qmInverse)
	assertEqualQM31(api, quotientWithM, quotientWithQM)

	return nil
}

type qm31InverseCircuit struct {
	Value [4]frontend.Variable
}

func (c *qm31InverseCircuit) Define(api frontend.API) error {
	m31Chip := NewM31Chip(api)
	cmChip := NewCM31Chip(m31Chip)
	qmChip := NewQM31Chip(cmChip)

	value := QM31{
		A: NewCM31(NewM31Unchecked(c.Value[0]), NewM31Unchecked(c.Value[1])),
		B: NewCM31(NewM31Unchecked(c.Value[2]), NewM31Unchecked(c.Value[3])),
	}
	inverse := qmChip.Inverse(value)

	product := qmChip.Mul(value, inverse)
	one := qmChip.One()
	api.AssertIsEqual(product.A.A.x, one.A.A.x)
	api.AssertIsEqual(product.A.B.x, one.A.B.x)
	api.AssertIsEqual(product.B.A.x, one.B.A.x)
	api.AssertIsEqual(product.B.B.x, one.B.B.x)
	return nil
}

type qm31InverseSimpleCircuit struct{}

func (c *qm31InverseSimpleCircuit) Define(api frontend.API) error {
	m31Chip := NewM31Chip(api)
	cmChip := NewCM31Chip(m31Chip)
	qmChip := NewQM31Chip(cmChip)

	newCM := func(a, b uint64) CM31 {
		return NewCM31(NewM31Unchecked(a), NewM31Unchecked(b))
	}

	qm := QM31{A: newCM(1, 2), B: newCM(3, 4)}
	inverse := qmChip.Inverse(qm)
	product := qmChip.Mul(qm, inverse)
	assertEqualQM31(api, product, qmChip.One())
	return nil
}

// ╔══════════════════════════════════╗
// ║          Test Functions          ║
// ╚══════════════════════════════════╝

func TestQM31Ops(t *testing.T) {
	assert := test.NewAssert(t)
	circuit := &qm31OpsCircuit{}
	witness := &qm31OpsCircuit{}

	assert.ProverSucceeded(circuit, witness,
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16),
		test.NoProverChecks(),
		test.NoFuzzing())
}

func TestQM31Inverse(t *testing.T) {
	assert := test.NewAssert(t)
	circuit := &qm31InverseCircuit{}
	witness := &qm31InverseCircuit{Value: [4]frontend.Variable{3, 5, 7, 11}}

	assert.ProverSucceeded(circuit, witness,
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16),
		test.NoProverChecks(),
		test.NoFuzzing())

	badWitness := &qm31InverseCircuit{Value: [4]frontend.Variable{0, 0, 0, 0}}
	assert.ProverFailed(circuit, badWitness,
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16),
		test.NoProverChecks(),
		test.NoFuzzing())
}

func TestQM31InverseSimple(t *testing.T) {
	assert := test.NewAssert(t)
	circuit := &qm31InverseSimpleCircuit{}
	witness := &qm31InverseSimpleCircuit{}

	assert.ProverSucceeded(circuit, witness,
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16),
		test.NoProverChecks(),
		test.NoFuzzing())
}

// ╔══════════════════════════════════╗
// ║          Helper Functions        ║
// ╚══════════════════════════════════╝

func assertEqualQM31(api frontend.API, got, want QM31) {
	assertEqualCM31(api, got.A, want.A)
	assertEqualCM31(api, got.B, want.B)
}
