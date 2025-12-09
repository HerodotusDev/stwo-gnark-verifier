package verifier

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/blake2s"
	"github.com/HerodotusDev/stwo-gnark-verifier/channel"
	"github.com/HerodotusDev/stwo-gnark-verifier/circle"
	"github.com/HerodotusDev/stwo-gnark-verifier/components"
	"github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components"
	"github.com/HerodotusDev/stwo-gnark-verifier/fri"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/HerodotusDev/stwo-gnark-verifier/utils"
	"github.com/HerodotusDev/stwo-gnark-verifier/variables"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

type VerifierChip struct {
	api     frontend.API `gnark:"-"`
	uapi    *uints.BinaryField[uints.U32]
	bapi    *uints.Bytes
	blake2s *blake2s.Blake2sChip
	channel *channel.Channel
	m31     *m31.M31Chip
	qm31    *m31.QM31Chip
	circle  *circle.CircleChip
}

func NewVerifierChip(api frontend.API) *VerifierChip {
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		panic(err)
	}
	bapi, err := uints.NewBytes(api)
	if err != nil {
		panic(err)
	}
	blake2sChip := blake2s.NewBlake2sChip(api)
	m31Chip := m31.NewM31Chip(api)
	qm31Chip := m31.NewQM31Chip(m31Chip)
	circleChip := circle.NewCircleChip(api, m31Chip, qm31Chip)
	channelChip := channel.NewChannel(api)
	return &VerifierChip{
		api:     api,
		uapi:    uapi,
		bapi:    bapi,
		blake2s: blake2sChip,
		channel: channelChip,
		m31:     m31Chip,
		qm31:    qm31Chip,
		circle:  circleChip,
	}
}

func (c *VerifierChip) Verify(proof variables.Proof, pcsConfig fri.PcsConfig, circuitData variables.CircuitData) {
	// Mix PCS configuration into the channel
	pcsConfig.MixInto(c.channel, c.uapi)

	// Initialize commitment verifier
	commitmentVerifier := fri.NewCommitmentSchemeVerifier(c.api, c.uapi, pcsConfig, circuitData)
	logSizes := proof.Claim.LogSizes(circuitData)

	// We assume that all components have `max_constraint_log_degree_bound()` returning `log_size() + 1`.
	// This should not include the preprocessed trace (hence calling MAX before adding preprocessed trace log sizes)
	compositionLogDegreeBound := cairo_components.MaxLogSize(c.api, logSizes)

	// Verify preprocessed trace commitment
	logSizes[cairo_components.PREPROCESSED_IDX] = cairo_components.PreprocessedLogSizes()
	preprocessedLogSizes := logSizes[cairo_components.PREPROCESSED_IDX]
	commitmentVerifier.Commit(cairo_components.PREPROCESSED_IDX, proof.StarkProof.Commitments[0], preprocessedLogSizes, c.channel)

	// Mix claim into channel
	proof.Claim.MixInto(c.channel, c.api, circuitData)

	// Verify main trace commitment
	commitmentVerifier.Commit(cairo_components.MAIN_IDX, proof.StarkProof.Commitments[1], logSizes[cairo_components.MAIN_IDX], c.channel)

	// Check Proof-of-Work nonce
	c.channel.MixAndCheckPowNonce(proof.InteractionPow, 24)

	// Draw interaction elements
	var cairoInteractionElements variables.CairoInteractionElements
	cairoInteractionElements.Draw(c.channel, c.qm31)

	// Verify Logup sum
	sum := components.LogupSum(c.qm31, proof.Claim, cairoInteractionElements, proof.InteractionClaim, circuitData)
	c.qm31.AssertEqual(sum, c.qm31.Zero())

	// Mix interaction claim into channel
	proof.InteractionClaim.MixInto(c.channel, circuitData)

	// Verify interaction trace commitment
	commitmentVerifier.Commit(cairo_components.INTERACTION_IDX, proof.StarkProof.Commitments[cairo_components.INTERACTION_IDX], logSizes[cairo_components.INTERACTION_IDX], c.channel)

	// Draw random coeff from channel for OODS
	randomCoeff := c.channel.DrawFelt()

	// Verify composition polynomial commitment
	compositionLogSizes := []frontend.Variable{compositionLogDegreeBound, compositionLogDegreeBound, compositionLogDegreeBound, compositionLogDegreeBound}
	commitmentVerifier.Commit(cairo_components.CP_IDX, proof.StarkProof.Commitments[cairo_components.CP_IDX], compositionLogSizes, c.channel)

	// Verify OODS
	oodsPoint := c.circle.GetRandomPoint(c.channel)
	components := components.NewComponents(c.api, c.m31, c.qm31, c.circle, cairoInteractionElements, proof.Claim, proof.InteractionClaim, oodsPoint, circuitData)
	c.VerifyOODS(proof.StarkProof.SampledValues, components, randomCoeff, circuitData)

	// Compute mask points
	maskPoints := proof.Claim.MaskPoints(c.api, oodsPoint, c.circle, circuitData)

	c.VerifyValues(commitmentVerifier, proof.StarkProof, maskPoints, circuitData)
}

func (c *VerifierChip) VerifyOODS(sampledValues [][][]m31.QM31, components *components.Components, randomCoeff m31.QM31, circuitData variables.CircuitData) {
	// Extract CP evaluation from sampled values
	composition_oods_eval := c.qm31.FromPartialEvals(
		sampledValues[cairo_components.CP_IDX][0][0],
		sampledValues[cairo_components.CP_IDX][1][0],
		sampledValues[cairo_components.CP_IDX][2][0],
		sampledValues[cairo_components.CP_IDX][3][0],
	)

	// evaluate constraints using sampled values
	constraints_oods_eval := components.Evaluate(sampledValues, randomCoeff, circuitData)

	// verify OODS
	c.qm31.AssertEqual(composition_oods_eval, constraints_oods_eval)
}

func (c *VerifierChip) VerifyValues(commitmentVerifier *fri.CommitmentSchemeVerifier, proof variables.StarkProof, maskPoints cairo_components.TreeMaskPoints, circuitData variables.CircuitData) {
	// Mix flatten sampled values into channel
	flattenedSampledValues := utils.FlattenTree(utils.FlattenTree(proof.SampledValues))
	c.channel.MixFelts(flattenedSampledValues)

	// Draw random coeff for FRI
	randomCoeff := c.channel.DrawFelt()

	// Compute bounds (column log sizes deduped, in decreasing order and not blew up)
	bounds := commitmentVerifier.Bounds()

	// Verification of commitment stage of FRI
	friVerifier := fri.NewFriVerifier(c.api, c.uapi, c.channel, c.qm31, c.circle, commitmentVerifier.PcsConfig.FriConfig, proof.FriProof, bounds)

	// Proof of work
	c.channel.MixAndCheckPowNonce(proof.ProofOfWork, int(commitmentVerifier.PcsConfig.PowBits))

	// Generate base layer queries and verify they match the hinted queries
	maxLogSize := bounds[0]
	baseLayerQueries := c.channel.GenerateBaseLayerQueries(maxLogSize, commitmentVerifier.PcsConfig.FriConfig.NQueries)
	queries := utils.GenerateQueries(c.api, baseLayerQueries, commitmentVerifier.PcsConfig.FriConfig.NQueries, circuitData.DedupedQueriesShape, circuitData.MaxLogSize)
	queriesLookup := utils.ToLookupTable(c.api, queries)

	// Verify merkle decommitments
	for treeIndex, tree := range commitmentVerifier.Trees {
		tree.Verify(queriesLookup, proof.QueriedValues[treeIndex], proof.Decommitments[treeIndex], circuitData.DedupedQueriesShape)
	}

	// Verify FRI quotients
	_ = friVerifier.FriQuotientEvaluations(proof.SampledValues, maskPoints, queries, proof.QueriedValues, randomCoeff, circuitData)
	// friVerifier.Verify(queries, friAnswers)
}
