package verifier

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/blake2s"
	"github.com/HerodotusDev/stwo-gnark-verifier/channel"
	"github.com/HerodotusDev/stwo-gnark-verifier/components"
	"github.com/HerodotusDev/stwo-gnark-verifier/fri"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/HerodotusDev/stwo-gnark-verifier/variables"
	"github.com/consensys/gnark/frontend"
)

type VerifierChip struct {
	api         frontend.API `gnark:"-"`
	blake2sChip *blake2s.Blake2sChip
	channelChip *channel.Channel
	m31         *m31.M31Chip
	qm31        *m31.QM31Chip
}

func NewVerifierChip(api frontend.API) *VerifierChip {
	blake2sChip := blake2s.NewBlake2sChip(api)
	m31Chip := m31.NewM31Chip(api)
	qm31Chip := m31.NewQM31Chip(m31Chip)
	channelChip := channel.NewChannel(api)
	return &VerifierChip{
		api:         api,
		blake2sChip: blake2sChip,
		channelChip: channelChip,
		m31:         m31Chip,
		qm31:        qm31Chip,
	}
}

func (c *VerifierChip) Verify(proof variables.Proof, pcsConfig fri.PcsConfig) {
	// Mix PCS configuration into the channel
	pcsConfig.MixInto(c.channelChip)

	// TODO: Verify commitments

	// TODO: Check Proof-of-Work nonce

	// Draw interaction elements
	var cairoInteractionElements variables.CairoInteractionElements
	cairoInteractionElements.Draw(c.channelChip, c.qm31)

	// Verify Logup sum
	// sum := components.LogupSum(c.qm31, proof.Claim, cairoInteractionElements, proof.InteractionClaim)
	// c.qm31.AssertEqual(sum, m31.NewQM31Unchecked(1880435071, 2071788161, 272129029, 1457783626))

	// Verify OODS
	// TODO: Draw oods point from channel
	oodsPoint := c.qm31.One()
	// TODO: Draw random coeff from channel
	random_coeff := c.qm31.One()
	components := components.NewComponents(c.api, c.m31, c.qm31, cairoInteractionElements, proof.Claim, proof.InteractionClaim, oodsPoint)
	c.VerifyOODS(proof.StarkProof.SampledValues, components, random_coeff)
}

func (c *VerifierChip) VerifyOODS(sampledValues [][][]m31.QM31, components *components.Components, random_coeff m31.QM31) {
	// TODO: Extract CP evaluation from sampled values
	composition_oods_eval := m31.NewQM31Unchecked(681221237, 2077141275, 236160070, 1930131422)

	// evaluate constraints using sampled values
	constraints_oods_eval := components.Evaluate(sampledValues, random_coeff)

	// verify OODS
	c.qm31.AssertEqual(composition_oods_eval, constraints_oods_eval)
}
