package components

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/HerodotusDev/stwo-gnark-verifier/variables"
	"github.com/consensys/gnark/frontend"
)

// A chip for OODS
type Components struct {
	api  frontend.API
	qm31 *m31.QM31Chip

	memoryAddressToId *MemoryAddressToIdComponent
}

// Creates a new OODS chip
func NewComponents(
	api frontend.API,
	qm31Chip *m31.QM31Chip,
	cairoInteractionElements variables.CairoInteractionElements,
	claim variables.CairoClaim,
	interactionClaim variables.CairoInteractionClaim,
	oodsPoint m31.QM31,
) *Components {
	memoryAddressToId := NewMemoryAddressToId(api, qm31Chip, cairoInteractionElements.MemoryAddressToId, claim.MemoryAddressToId, interactionClaim.MemoryAddressToId, oodsPoint)

	return &Components{
		api:               api,
		qm31:              qm31Chip,
		memoryAddressToId: memoryAddressToId,
	}
}

func (c *Components) Evaluate(sampledValues [][][]m31.QM31, random_coeff m31.QM31) m31.QM31 {
	sum := c.qm31.Zero()
	sum = c.memoryAddressToId.Evaluate(sum, sampledValues, random_coeff)
	return sum
}
