package components

import (
	"fmt"
	"testing"

	"github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/HerodotusDev/stwo-gnark-verifier/variables"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
)

// Sum value comes from the following cairo1 test:
//
//	fn test_memory_address_to_id_constraints_regression() {
//		let mut sum: QM31 = Zero::zero();
//		let params = ConstraintParams {
//			MemoryAddressToId_alpha0: One::one(),
//			MemoryAddressToId_alpha1: One::one(),
//			MemoryAddressToId_z: QM31Trait::from_fixed_array([M31Trait::reduce_u32(1), M31Trait::reduce_u32(2), M31Trait::reduce_u32(3), M31Trait::reduce_u32(4)]),
//			claimed_sum: One::one(),
//			seq: One::one() + One::one(),
//			column_size: M31Trait::reduce_u32(16),
//		};
//		let random_coeff: QM31 = One::one();
//		let domain_vanish_at_point_inv: QM31 = One::one();
//		let mut trace_mask_values = array![ones].span();
//		let mut interaction_trace_mask_values = array![ones].span();
//		evaluate_constraints_at_point(
//			ref sum,
//			ref trace_mask_values,
//			ref interaction_trace_mask_values,
//			params,
//			random_coeff,
//			domain_vanish_at_point_inv,
//		);
//
// println!("sum: {}", sum);
// }
type componentsEvaluateCircuit struct{}

func (c *componentsEvaluateCircuit) Define(api frontend.API) error {
	m31Chip := m31.NewM31Chip(api)
	qm31Chip := m31.NewQM31Chip(m31Chip)

	interactionElements := variables.CairoInteractionElements{
		MemoryAddressToId: qm31Chip.DummyInteractionElements(2),
	}
	claim := variables.CairoClaim{
		MemoryAddressToId: cairo_components.MemoryAddressToIdClaim{LogSize: uints.NewU8(4)},
	}
	interactionClaim := variables.CairoInteractionClaim{
		MemoryAddressToId: cairo_components.MemoryAddressToIdInteractionClaim{ClaimedSum: qm31Chip.One()},
	}
	oodsPoint := qm31Chip.One()

	component := NewComponents(api, m31Chip, qm31Chip, interactionElements, claim, interactionClaim, oodsPoint)
	sampledValues := dummySampledValues(api, qm31Chip)
	randomCoeff := qm31Chip.One()

	result := component.Evaluate(sampledValues, randomCoeff)
	expectedResult := m31.NewQM31Unchecked(2013253660, 1744821975, 1879036222, 536861227)
	qm31Chip.AssertEqual(result, expectedResult)
	return nil
}

func dummySampledValues(api frontend.API, qm31Chip *m31.QM31Chip) [][][]m31.QM31 {
	// Layout mirrors the slices consumed inside MemoryAddressToIdComponent.Evaluate.
	sampledValues := make([][][]m31.QM31, cairo_components.CP_IDX+1)

	preprocessed := make([][]m31.QM31, len(cairo_components.PreprocessedColumns))
	main := make([][]m31.QM31, 16)
	interaction := make([][]m31.QM31, 16)
	one := qm31Chip.One()
	two := qm31Chip.Add(one, one)

	for i := range main {
		main[i] = []m31.QM31{one}
	}
	for i := range interaction {
		if i >= 12 {
			interaction[i] = []m31.QM31{one, one}
			continue
		}
		interaction[i] = []m31.QM31{one}
	}

	seqColumnKey := cairo_components.NewPreprocessedColumnSeq(uints.NewU8(4)).Key(api)
	found := false
	for i, column := range cairo_components.PreprocessedColumns {
		if column.Key(api) == seqColumnKey {
			preprocessed[i] = []m31.QM31{two}
			found = true
			break
		}
	}
	if !found {
		panic("Seq(4) preprocessed column not found in test setup")
	}

	sampledValues[cairo_components.PREPROCESSED_IDX] = preprocessed
	sampledValues[cairo_components.MAIN_IDX] = main
	sampledValues[cairo_components.INTERACTION_IDX] = interaction
	return sampledValues
}

func TestComponentsEvaluateCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	circuit := &componentsEvaluateCircuit{}
	witness := &componentsEvaluateCircuit{}

	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		t.Fatalf("compile circuit: %v", err)
	}
	count := cs.GetNbConstraints()
	fmt.Printf("TestComponentsEvaluateCircuit constraints: %d\n", count)

	assert.CheckCircuit(circuit,
		test.WithValidAssignment(witness),
		test.WithCurves(ecc.BN254),
	)
}
