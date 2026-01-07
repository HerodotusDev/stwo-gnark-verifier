// Tests for qm31 operations come from :
// https://github.com/starkware-libs/stwo/blob/dev/crates/stwo/src/core/fields/qm31.rs

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

// Circuit for QM31 operations tests
type qm31OpsCircuit struct{}

func (c *qm31OpsCircuit) Define(api frontend.API) error {
	m31Chip := NewM31Chip(api)
	qmChip := NewQM31Chip(m31Chip)

	qm0 := NewQM31Unchecked(1, 2, 3, 4)
	qm1 := NewQM31Unchecked(4, 5, 6, 7)
	m := NewM31Unchecked(8)
	qm := NewQM31FromM31(m)
	qm0xqm1 := NewQM31Unchecked(PRIME_U64-71, 93, PRIME_U64-16, 50)

	sum := qmChip.Add(qm0, qm1)
	qmChip.AssertEqual(sum, NewQM31Unchecked(5, 7, 9, 11))

	sumWithM31 := qmChip.Add(qm1, NewQM31FromM31(m))
	sumWithQM := qmChip.Add(qm1, qm)
	qmChip.AssertEqual(sumWithM31, sumWithQM)

	product := qmChip.Mul(qm0, qm1)
	qmChip.AssertEqual(product, qm0xqm1)

	prodWithM := qmChip.MulM31(qm1, m)
	prodWithQM := qmChip.Mul(qm1, qm)
	qmChip.AssertEqual(prodWithM, prodWithQM)

	neg := qmChip.Neg(qm0)
	qmChip.AssertEqual(neg, NewQM31Unchecked(PRIME_U64-1, PRIME_U64-2, PRIME_U64-3, PRIME_U64-4))

	diff := qmChip.Sub(qm0, qm1)
	qmChip.AssertEqual(diff, NewQM31Unchecked(PRIME_U64-3, PRIME_U64-3, PRIME_U64-3, PRIME_U64-3))

	diffWithM31 := qmChip.Sub(qm1, NewQM31FromM31(m))
	diffWithQM := qmChip.Sub(qm1, qm)
	qmChip.AssertEqual(diffWithM31, diffWithQM)

	qm1Inverse := qmChip.Inverse(qm1)
	quotient := qmChip.Mul(qm0xqm1, qm1Inverse)
	qmChip.AssertEqual(quotient, qm0)

	mInverse, hasMinv := m31Chip.Inverse(m)
	api.AssertIsEqual(hasMinv, frontend.Variable(1))
	quotientWithM := qmChip.MulM31(qm1, mInverse)
	qmInverse := qmChip.Inverse(qm)
	quotientWithQM := qmChip.Mul(qm1, qmInverse)
	qmChip.AssertEqual(quotientWithM, quotientWithQM)

	return nil
}

// Circuit for QM31 inversion tests
type qm31InverseCircuit struct {
	Value [4]M31
}

func (c *qm31InverseCircuit) Define(api frontend.API) error {
	m31Chip := NewM31Chip(api)
	qmChip := NewQM31Chip(m31Chip)

	value := NewQM31FromComponents(c.Value[0], c.Value[1], c.Value[2], c.Value[3])
	inverse := qmChip.Inverse(value)

	product := qmChip.Mul(value, inverse)
	qmChip.AssertEqual(product, qmChip.One())
	return nil
}

// Circuit for QM31 encoding/decoding tests
type qm31EncodeDecodeCircuit struct {
	Value QM31
}

func (c *qm31EncodeDecodeCircuit) Define(api frontend.API) error {
	m31Chip := NewM31Chip(api)
	qmChip := NewQM31Chip(m31Chip)

	value := c.Value
	encodedValue := qmChip.EncodeNative(value)
	decodedValue := qmChip.DecodeNative(encodedValue)
	qmChip.AssertEqual(decodedValue, value)
	return nil
}

// ╔══════════════════════════════════╗
// ║          Test Functions          ║
// ╚══════════════════════════════════╝

// Test QM31 operations
func TestQM31Ops(t *testing.T) {
	assert := test.NewAssert(t)
	circuit := &qm31OpsCircuit{}
	witness := &qm31OpsCircuit{}

	assert.CheckCircuit(circuit,
		test.WithValidAssignment(witness),
		test.WithCurves(ecc.BN254),
	)
}

// Test QM31 inversion
func TestQM31Inverse(t *testing.T) {
	assert := test.NewAssert(t)
	circuit := &qm31InverseCircuit{}
	witness := &qm31InverseCircuit{Value: [4]M31{NewM31Unchecked(3), NewM31Unchecked(5), NewM31Unchecked(7), NewM31Unchecked(11)}}

	assert.CheckCircuit(circuit,
		test.WithValidAssignment(witness),
		test.WithCurves(ecc.BN254),
	)

	badWitness := &qm31InverseCircuit{Value: [4]M31{NewM31Unchecked(0), NewM31Unchecked(0), NewM31Unchecked(0), NewM31Unchecked(0)}}
	assert.CheckCircuit(circuit,
		test.WithInvalidAssignment(badWitness),
		test.WithCurves(ecc.BN254),
	)
}

// Test QM31 encoding/decoding
func TestQM31EncodeDecode(t *testing.T) {
	assert := test.NewAssert(t)
	circuit := &qm31EncodeDecodeCircuit{}
	witness := &qm31EncodeDecodeCircuit{Value: NewQM31Unchecked(1, 2, 3, 4)}

	assert.CheckCircuit(circuit,
		test.WithValidAssignment(witness),
		test.WithCurves(ecc.BN254),
	)
}
