package verifier

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/blake2s"
	"github.com/HerodotusDev/stwo-gnark-verifier/channel"
	"github.com/HerodotusDev/stwo-gnark-verifier/circle"
	"github.com/HerodotusDev/stwo-gnark-verifier/components"
	"github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components"
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
	circle      *circle.CircleChip
}

func NewVerifierChip(api frontend.API) *VerifierChip {
	blake2sChip := blake2s.NewBlake2sChip(api)
	m31Chip := m31.NewM31Chip(api)
	qm31Chip := m31.NewQM31Chip(m31Chip)
	circleChip := circle.NewCircleChip(api, m31Chip, qm31Chip)
	channelChip := channel.NewChannel(api)
	return &VerifierChip{
		api:         api,
		blake2sChip: blake2sChip,
		channelChip: channelChip,
		m31:         m31Chip,
		qm31:        qm31Chip,
		circle:      circleChip,
	}
}

func (c *VerifierChip) Verify(proof variables.Proof, pcsConfig fri.PcsConfig) {
	// Mix PCS configuration into the channel
	pcsConfig.MixInto(c.channelChip)

	// Initialize commitment verifier
	commitmentVerifier := NewCommitmentSchemeVerifier(c.api, pcsConfig)
	logSizes := proof.Claim.LogSizes()

	// Verify preprocessed trace commitment
	logSizes[cairo_components.PREPROCESSED_IDX] = cairo_components.PreprocessedLogSizes()
	preprocessedLogSizes := logSizes[cairo_components.PREPROCESSED_IDX]
	commitmentVerifier.Commit(cairo_components.PREPROCESSED_IDX, proof.StarkProof.Commitments[0], preprocessedLogSizes, c.channelChip)

	// Mix claim into channel
	proof.Claim.MixInto(c.channelChip, c.api)

	// Verify main trace commitment
	commitmentVerifier.Commit(cairo_components.MAIN_IDX, proof.StarkProof.Commitments[1], logSizes[cairo_components.MAIN_IDX], c.channelChip)

	// Check Proof-of-Work nonce
	c.channelChip.MixAndCheckPowNonce(proof.InteractionPow, 24)

	// Draw interaction elements
	var cairoInteractionElements variables.CairoInteractionElements
	cairoInteractionElements.Draw(c.channelChip, c.qm31)

	// Verify Logup sum
	sum := components.LogupSum(c.qm31, proof.Claim, cairoInteractionElements, proof.InteractionClaim)
	c.qm31.AssertEqual(sum, c.qm31.Zero())

	// Mix interaction claim into channel
	proof.InteractionClaim.MixInto(c.channelChip)

	// Verify interaction trace commitment
	commitmentVerifier.Commit(cairo_components.INTERACTION_IDX, proof.StarkProof.Commitments[cairo_components.INTERACTION_IDX], logSizes[cairo_components.INTERACTION_IDX], c.channelChip)

	// Draw random coeff from channel for OODS
	randomCoeff := c.channelChip.DrawFelt()

	// We assume that all components have `max_constraint_log_degree_bound()` returning `log_size() + 1`.
	compositionLogDegreeBound := cairo_components.MaxLogSize(logSizes) + 1
	compositionLogSizes := []uint32{compositionLogDegreeBound, compositionLogDegreeBound, compositionLogDegreeBound, compositionLogDegreeBound}
	commitmentVerifier.Commit(cairo_components.CP_IDX, proof.StarkProof.Commitments[cairo_components.CP_IDX], compositionLogSizes, c.channelChip)

	// Verify OODS
	oodsPoint := c.circle.GetRandomPoint(c.channelChip)
	components := components.NewComponents(c.api, c.m31, c.qm31, c.circle, cairoInteractionElements, proof.Claim, proof.InteractionClaim, oodsPoint)
	c.VerifyOODS(proof.StarkProof.SampledValues, components, randomCoeff)

	c.VerifyValues(commitmentVerifier, proof.StarkProof)
}

func (c *VerifierChip) VerifyOODS(sampledValues [][][]m31.QM31, components *components.Components, randomCoeff m31.QM31) {
	// Extract CP evaluation from sampled values
	composition_oods_eval := c.qm31.FromPartialEvals(
		sampledValues[cairo_components.CP_IDX][0][0],
		sampledValues[cairo_components.CP_IDX][1][0],
		sampledValues[cairo_components.CP_IDX][2][0],
		sampledValues[cairo_components.CP_IDX][3][0],
	)

	// evaluate constraints using sampled values
	constraints_oods_eval := components.Evaluate(sampledValues, randomCoeff)

	// verify OODS
	c.qm31.AssertEqual(composition_oods_eval, constraints_oods_eval)
}

func (c *VerifierChip) VerifyValues(commitmentVerifier *CommitmentSchemeVerifier, proof variables.StarkProof) {
	// Mix flatten sampled values into channel
	flattenedSampledValues := make([]m31.QM31, 0)
	for _, sampledValues := range proof.SampledValues {
		for _, sampledValue := range sampledValues {
			flattenedSampledValues = append(flattenedSampledValues, sampledValue...)
		}
	}
	c.channelChip.MixFelts(flattenedSampledValues)

	// Draw random coeff for FRI
	_ = c.channelChip.DrawFelt()

	// Compute bounds (column log sizes deduped, in decreasing order and not blew up)
	bounds := commitmentVerifier.bounds()

	// Verification of commitment stage of FRI
	_ = fri.NewFriVerifier(c.channelChip, c.circle, commitmentVerifier.pcsConfig.FriConfig, proof.FriProof, bounds)
}
