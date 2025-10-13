package components

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
)

type MemoryAddressToIdComponent struct {
	api  frontend.API
	qm31 *m31.QM31Chip

	interactionElements m31.InteractionElements
	logSize             uint32
	claimedSum          m31.QM31
}

func NewMemoryAddressToId(api frontend.API, qm31 *m31.QM31Chip, interactionElements m31.InteractionElements, logSize uint32, claimedSum m31.QM31, oodsPoint m31.QM31) *MemoryAddressToIdComponent {
	// TODO: Compute vanishEval from the oods point and logSize
	return &MemoryAddressToIdComponent{api: api, qm31: qm31, interactionElements: interactionElements, logSize: logSize, claimedSum: claimedSum}
}

func (c *MemoryAddressToIdComponent) Evaluate(sum m31.QM31, sampledValues [][][]m31.QM31, random_coeff m31.QM31) m31.QM31 {
	// TODO: Handle preprocessed trace
	// seq := c.qm31.One()
	return sum
}
