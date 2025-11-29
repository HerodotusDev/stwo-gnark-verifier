package verifier

import (
	"fmt"

	"github.com/HerodotusDev/stwo-gnark-verifier/blake2s"
	"github.com/HerodotusDev/stwo-gnark-verifier/channel"
	"github.com/HerodotusDev/stwo-gnark-verifier/circle"
	"github.com/HerodotusDev/stwo-gnark-verifier/components"
	"github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components"
	"github.com/HerodotusDev/stwo-gnark-verifier/fri"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/HerodotusDev/stwo-gnark-verifier/variables"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

type VerifierChip struct {
	api         frontend.API `gnark:"-"`
	uapi        *uints.BinaryField[uints.U32]
	blake2sChip *blake2s.Blake2sChip
	channelChip *channel.Channel
	m31         *m31.M31Chip
	qm31        *m31.QM31Chip
	circle      *circle.CircleChip
}

func NewVerifierChip(api frontend.API) *VerifierChip {
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		panic(err)
	}
	blake2sChip := blake2s.NewBlake2sChip(api)
	m31Chip := m31.NewM31Chip(api)
	qm31Chip := m31.NewQM31Chip(m31Chip)
	circleChip := circle.NewCircleChip(api, m31Chip, qm31Chip)
	channelChip := channel.NewChannel(api)
	return &VerifierChip{
		api:         api,
		uapi:        uapi,
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

	// We assume that all components have `max_constraint_log_degree_bound()` returning `log_size() + 1`.
	// This should not include the preprocessed trace (hence calling MAX before adding preprocessed trace log sizes)
	compositionLogDegreeBound := cairo_components.MaxLogSize(logSizes) + 1

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

	// Verify composition polynomial commitment
	compositionLogSizes := []uint32{compositionLogDegreeBound, compositionLogDegreeBound, compositionLogDegreeBound, compositionLogDegreeBound}
	commitmentVerifier.Commit(cairo_components.CP_IDX, proof.StarkProof.Commitments[cairo_components.CP_IDX], compositionLogSizes, c.channelChip)

	// Verify OODS
	oodsPoint := c.circle.GetRandomPoint(c.channelChip)
	components := components.NewComponents(c.api, c.m31, c.qm31, c.circle, cairoInteractionElements, proof.Claim, proof.InteractionClaim, oodsPoint)
	c.VerifyOODS(proof.StarkProof.SampledValues, components, randomCoeff)

	// Compute mask points
	maskPoints := proof.Claim.MaskPoints(c.api, oodsPoint, c.circle)
	// DEBUG: Verify that there is a point for each sampled value (no constraints enforced)
	checkMaskPoints(maskPoints, proof.StarkProof.SampledValues)

	c.VerifyValues(commitmentVerifier, proof.StarkProof, proof.CircuitHints.Queries, maskPoints)
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

func (c *VerifierChip) VerifyValues(commitmentVerifier *CommitmentSchemeVerifier, proof variables.StarkProof, queries [][]int, maskPoints cairo_components.TreeMaskPoints) {
	// Mix flatten sampled values into channel
	flattenedSampledValues := make([]m31.QM31, 0)
	for _, sampledValues := range proof.SampledValues {
		for _, sampledValue := range sampledValues {
			flattenedSampledValues = append(flattenedSampledValues, sampledValue...)
		}
	}
	c.channelChip.MixFelts(flattenedSampledValues)

	// Draw random coeff for FRI
	randomCoeff := c.channelChip.DrawFelt()

	// Compute bounds (column log sizes deduped, in decreasing order and not blew up)
	bounds := commitmentVerifier.bounds()

	// Verification of commitment stage of FRI
	friVerifier := fri.NewFriVerifier(c.api, c.uapi, c.channelChip, c.qm31, c.circle, commitmentVerifier.pcsConfig.FriConfig, proof.FriProof, bounds)

	// Proof of work
	c.channelChip.MixAndCheckPowNonce(proof.ProofOfWork, int(commitmentVerifier.pcsConfig.PowBits))

	// Generate base layer queries and verify they match the hinted queries
	baseLayerQueries := friVerifier.GenerateBaseLayerQueries(c.channelChip, c.uapi, commitmentVerifier.pcsConfig.FriConfig.NQueries)
	friVerifier.VerifyQueries(queries[len(queries)-1], baseLayerQueries)

	// Verify merkle decommitments
	for treeIndex, tree := range commitmentVerifier.trees {
		tree.Verify(queries, proof.QueriedValues[treeIndex], proof.Decommitments[treeIndex])
	}

	// Verify FRI quotients
	quotientEvaluations := friVerifier.FriQuotientEvaluations(commitmentVerifier.columnLogSizes(), proof.SampledValues, maskPoints, queries, proof.QueriedValues, randomCoeff)
	fmt.Println("quotientEvaluations", quotientEvaluations)
}

func checkMaskPoints(maskPoints cairo_components.TreeMaskPoints, sampledValues [][][]m31.QM31) {
	if len(maskPoints) != len(sampledValues) {
		panic("tree length mismatch")
	}
	for treeIndex, tree := range maskPoints {
		if len(tree) != len(sampledValues[treeIndex]) {
			panic(fmt.Sprintf("column length mismatch: %d != %d", len(tree), len(sampledValues[treeIndex])))
		}
		for columnIndex, column := range tree {
			if len(column) != len(sampledValues[treeIndex][columnIndex]) {
				panic(fmt.Sprintf("sample length mismatch (tree index: %d, column index: %d): %d != %d", treeIndex, columnIndex, len(column), len(sampledValues[treeIndex][columnIndex])))
			}
		}
	}
}
