package circle

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"

	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
)

type circleBasePointCircuit struct{}

func (c *circleBasePointCircuit) Define(api frontend.API) error {
	m31Chip := m31.NewM31Chip(api)
	qm31Chip := m31.NewQM31Chip(m31Chip)
	circleChip := NewCircleChip(api, m31Chip, qm31Chip)

	cases := []struct {
		scalar   uint32
		expected BasePoint
	}{
		{scalar: 1, expected: NewBasePoint(m31.NewM31Unchecked(2), m31.NewM31Unchecked(1268011823))},
		{scalar: 3, expected: NewBasePoint(m31.NewM31Unchecked(26), m31.NewM31Unchecked(1840308169))},
		{scalar: 5, expected: NewBasePoint(m31.NewM31Unchecked(362), m31.NewM31Unchecked(873982426))},
		{scalar: 17, expected: NewBasePoint(m31.NewM31Unchecked(495401635), m31.NewM31Unchecked(1386042346))},
		{scalar: 21, expected: NewBasePoint(m31.NewM31Unchecked(1605013240), m31.NewM31Unchecked(168852095))},
	}

	for _, tc := range cases {
		result := circleChip.BaseMul(baseCircleGenerator, uints.NewU32(tc.scalar))
		m31Chip.AssertEqual(result.X, tc.expected.X)
		m31Chip.AssertEqual(result.Y, tc.expected.Y)
	}

	order := uint32(1) << CircleLogOrder
	negative := circleChip.BaseMul(baseCircleGenerator, uints.NewU32(order-21))
	m31Chip.AssertEqual(negative.X, m31.NewM31Unchecked(1605013240))
	m31Chip.AssertEqual(negative.Y, m31.NewM31Unchecked(1978631552))

	return nil
}

func TestCircleBasePointReferenceValues(t *testing.T) {
	assert := test.NewAssert(t)
	circuit := &circleBasePointCircuit{}
	assert.CheckCircuit(circuit,
		test.WithValidAssignment(circuit),
		test.WithCurves(ecc.BN254),
	)
}

type circleCanonicVanishingCircuit struct{}

func (c *circleCanonicVanishingCircuit) Define(api frontend.API) error {
	m31Chip := m31.NewM31Chip(api)
	qm31Chip := m31.NewQM31Chip(m31Chip)
	circleChip := NewCircleChip(api, m31Chip, qm31Chip)

	canonic := NewCanonicCoset(circleChip, 6)
	cases := []struct {
		index           uint32
		expectedValue   m31.QM31
		expectedInverse m31.QM31
	}{
		{
			index:           0x01020304,
			expectedValue:   m31.NewQM31Unchecked(962857441, 0, 0, 0),
			expectedInverse: m31.NewQM31Unchecked(264010565, 0, 0, 0),
		},
		{
			index:           0x000ABCDE,
			expectedValue:   m31.NewQM31Unchecked(895155682, 0, 0, 0),
			expectedInverse: m31.NewQM31Unchecked(470759870, 0, 0, 0),
		},
	}

	for _, tc := range cases {
		index := newPointIndex(circleChip, uints.NewU32(tc.index))
		point := circleChip.LiftBasePoint(index.Point())
		value := circleChip.CosetVanishing(canonic.Coset(), point)
		qm31Chip.AssertEqual(value, tc.expectedValue)

		inverse := circleChip.CanonicVanishingInverse(6, point)
		qm31Chip.AssertEqual(inverse, tc.expectedInverse)
	}

	return nil
}

func TestCircleCanonicVanishingInverseReferenceValues(t *testing.T) {
	assert := test.NewAssert(t)
	circuit := &circleCanonicVanishingCircuit{}
	assert.CheckCircuit(circuit,
		test.WithValidAssignment(circuit),
		test.WithCurves(ecc.BN254),
	)
}
