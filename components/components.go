package components

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/HerodotusDev/stwo-gnark-verifier/variables"
	"github.com/consensys/gnark/frontend"
)

// A chip for OODS
type Components struct {
	api  frontend.API
	m31  *m31.M31Chip
	qm31 *m31.QM31Chip

	memoryAddressToId *cairo_components.MemoryAddressToIdComponent
}

// Creates a new OODS chip
func NewComponents(
	api frontend.API,
	m31 *m31.M31Chip,
	qm31Chip *m31.QM31Chip,
	cairoInteractionElements variables.CairoInteractionElements,
	claim variables.CairoClaim,
	interactionClaim variables.CairoInteractionClaim,
	oodsPoint m31.QM31,
) *Components {
	memoryAddressToId := cairo_components.NewMemoryAddressToId(
		api,
		qm31Chip,
		cairoInteractionElements.MemoryAddressToId,
		claim.MemoryAddressToId,
		interactionClaim.MemoryAddressToId,
		oodsPoint,
	)

	return &Components{
		api:               api,
		m31:               m31,
		qm31:              qm31Chip,
		memoryAddressToId: memoryAddressToId,
	}
}

func (c *Components) Evaluate(sampledValues [][][]m31.QM31, random_coeff m31.QM31) m31.QM31 {
	// Prepare sampled values
	preprocessedSampledValuesRaw := sampledValues[cairo_components.PREPROCESSED_IDX]
	preprocessedSampledValues := cairo_components.NewPreprocessedSampledValues(c.api, c.m31, preprocessedSampledValuesRaw)
	traceSampledValues := sampledValues[cairo_components.MAIN_IDX]
	interactionSampledValues := sampledValues[cairo_components.INTERACTION_IDX]

	// Evaluate components
	sum := c.qm31.Zero()
	sum = c.memoryAddressToId.Evaluate(sum, preprocessedSampledValues, traceSampledValues, interactionSampledValues, random_coeff)

	return sum
}
