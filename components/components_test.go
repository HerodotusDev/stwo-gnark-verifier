package components

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
)

// ╔══════════════════════════════════╗
// ║        Expected Sums             ║
// ╚══════════════════════════════════╝
var expectedSums = loadExpectedSums()

func loadExpectedSums() map[string]qm31Literal {
	path := expectedSumsJSONPath()
	data, err := os.ReadFile(path)
	if err != nil {
		panic(fmt.Sprintf("failed to read expected sums file %q: %v", path, err))
	}

	var sums map[string]qm31Literal
	if err := json.Unmarshal(data, &sums); err != nil {
		panic(fmt.Sprintf("failed to decode expected sums file %q: %v", path, err))
	}

	return sums
}

func expectedSumsJSONPath() string {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		panic("unable to determine expected sums path")
	}
	return filepath.Join(filepath.Dir(filename), "..", "test_data", "oods_sums.json")
}

// ╔══════════════════════════════════╗
// ║    Component Evaluation Test     ║
// ╚══════════════════════════════════╝
func TestCairoComponentAtomicEvaluations(t *testing.T) {
	fixtures := []componentFixture{
		newAddApOpcodeFixture(expectedSums["add_ap_opcode"]),
		newAddModBuiltinFixture(expectedSums["add_mod_builtin"]),
		newAddOpcodeFixture(expectedSums["add_opcode"]),
		newAddSmallOpcodeFixture(expectedSums["add_opcode_small"]),
		newAssertEqDoubleDerefOpcodeFixture(expectedSums["assert_eq_opcode_double_deref"]),
		newAssertEqImmOpcodeFixture(expectedSums["assert_eq_opcode_imm"]),
		newAssertEqOpcodeFixture(expectedSums["assert_eq_opcode"]),
		newBitwiseBuiltinFixture(expectedSums["bitwise_builtin"]),
		newBlakeCompressOpcodeFixture(expectedSums["blake_compress_opcode"]),
		newBlakeGFixture(expectedSums["blake_g"]),
		newBlakeRoundFixture(expectedSums["blake_round"]),
		newBlakeRoundSigmaFixture(expectedSums["blake_round_sigma"]),
		newCallOpcodeFixture(expectedSums["call_opcode"]),
		newCallRelImmOpcodeFixture(expectedSums["call_opcode_rel_imm"]),
		newCube252Fixture(expectedSums["cube_252"]),
		newGenericOpcodeFixture(expectedSums["generic_opcode"]),
		newJnzOpcodeFixture(expectedSums["jnz_opcode"]),
		newJnzTakenOpcodeFixture(expectedSums["jnz_opcode_taken"]),
		newJumpDoubleDerefOpcodeFixture(expectedSums["jump_opcode_double_deref"]),
		newJumpOpcodeFixture(expectedSums["jump_opcode"]),
		newJumpRelImmOpcodeFixture(expectedSums["jump_opcode_rel_imm"]),
		newJumpRelOpcodeFixture(expectedSums["jump_opcode_rel"]),
		newMemoryAddressToIdFixture(expectedSums["memory_address_to_id"]),
		newMemoryIdToBigBigFixture(expectedSums["memory_id_to_big_big_component"]),
		newMemoryIdToBigSmallFixture(expectedSums["memory_id_to_big_small_component"]),
		newMulModBuiltinFixture(expectedSums["mul_mod_builtin"]),
		newMulOpcodeFixture(expectedSums["mul_opcode"]),
		newMulSmallOpcodeFixture(expectedSums["mul_opcode_small"]),
		newPartialEcMulFixture(expectedSums["partial_ec_mul"]),
		newPedersenBuiltinFixture(expectedSums["pedersen_builtin"]),
		newPedersenPointsTableFixture(expectedSums["pedersen_points_table"]),
		newPoseidon3PartialRoundsChainFixture(expectedSums["poseidon_3_partial_rounds_chain"]),
		newPoseidonBuiltinFixture(expectedSums["poseidon_builtin"]),
		newPoseidonFullRoundChainFixture(expectedSums["poseidon_full_round_chain"]),
		newPoseidonRoundKeysFixture(expectedSums["poseidon_round_keys"]),
		newQm31OpcodeFixture(expectedSums["qm31_opcode"]),
		newRangeCheck11Fixture(expectedSums["range_check_11"]),
		newRangeCheck12Fixture(expectedSums["range_check_12"]),
		newRangeCheck18Fixture(expectedSums["range_check_18"]),
		newRangeCheck19Fixture(expectedSums["range_check_19"]),
		newRangeCheck3_3_3_3_3Fixture(expectedSums["range_check_3_3_3_3_3"]),
		newRangeCheck3_6_6_3Fixture(expectedSums["range_check_3_6_6_3"]),
		newRangeCheck4_3Fixture(expectedSums["range_check_4_3"]),
		newRangeCheck4_4_4_4Fixture(expectedSums["range_check_4_4_4_4"]),
		newRangeCheck4_4Fixture(expectedSums["range_check_4_4"]),
		newRangeCheck5_4Fixture(expectedSums["range_check_5_4"]),
		newRangeCheck6Fixture(expectedSums["range_check_6"]),
		newRangeCheck7_2_5Fixture(expectedSums["range_check_7_2_5"]),
		newRangeCheck8Fixture(expectedSums["range_check_8"]),
		newRangeCheck9_9Fixture(expectedSums["range_check_9_9"]),
		newRangeCheckBuiltin128Fixture(expectedSums["range_check_builtin_bits_128"]),
		newRangeCheckBuiltin96Fixture(expectedSums["range_check_builtin_bits_96"]),
		newRangeCheckFelt252Width27Fixture(expectedSums["range_check_felt_252_width_27"]),
		newRetOpcodeFixture(expectedSums["ret_opcode"]),
		newTripleXor32Fixture(expectedSums["triple_xor_32"]),
		newVerifyBitwiseXor12Fixture(expectedSums["verify_bitwise_xor_12"]),
		newVerifyBitwiseXor4Fixture(expectedSums["verify_bitwise_xor_4"]),
		newVerifyBitwiseXor7Fixture(expectedSums["verify_bitwise_xor_7"]),
		newVerifyBitwiseXor8Fixture(expectedSums["verify_bitwise_xor_8"]),
		newVerifyBitwiseXor9Fixture(expectedSums["verify_bitwise_xor_9"]),
		newVerifyInstructionFixture(expectedSums["verify_instruction"]),
	}

	for _, fixture := range fixtures {
		t.Run(fixture.Name(), func(t *testing.T) {
			assert := test.NewAssert(t)
			circuit := &componentEvaluationCircuit{fixture: fixture}
			witness := &componentEvaluationCircuit{fixture: fixture}

			assert.CheckCircuit(circuit,
				test.WithValidAssignment(witness),
				test.WithCurves(ecc.BN254),
			)
		})
	}
}

type componentEvaluationCircuit struct {
	fixture componentFixture
}

func (c *componentEvaluationCircuit) Define(api frontend.API) error {
	if c.fixture == nil {
		return fmt.Errorf("component fixture must not be nil")
	}

	m31Chip := m31.NewM31Chip(api)
	qm31Chip := m31.NewQM31Chip(m31Chip)

	ctx := componentContext{
		api:      api,
		m31Chip:  m31Chip,
		qm31Chip: qm31Chip,
	}

	component := c.fixture.Build(ctx)
	if component == nil {
		return fmt.Errorf("fixture %s returned a nil component", c.fixture.Name())
	}

	preprocessedRaw, traceRaw, interactionRaw := c.fixture.SampledValues(ctx)
	preprocessed := cairo_components.NewPreprocessedSampledValues(api, m31Chip, preprocessedRaw)
	traces := cairo_components.NewTraces(preprocessed, traceRaw, interactionRaw)

	sum := qm31Chip.Zero()
	sum = component.Evaluate(sum, traces, qm31Chip.One())

	qm31Chip.AssertEqual(sum, c.fixture.ExpectedSum().ToQM31())
	return nil
}

// ╔══════════════════════════════════╗
// ║        Fixture Plumbing          ║
// ╚══════════════════════════════════╝

type componentFixture interface {
	Name() string
	Build(componentContext) componentUnderTest
	SampledValues(componentContext) ([][]m31.QM31, [][]m31.QM31, [][]m31.QM31)
	ExpectedSum() qm31Literal
}

type componentContext struct {
	api      frontend.API
	m31Chip  *m31.M31Chip
	qm31Chip *m31.QM31Chip
}

type componentUnderTest interface {
	Evaluate(
		sum m31.QM31,
		traces *cairo_components.Traces,
		randomCoeff m31.QM31,
	) m31.QM31
}

// ╔══════════════════════════════════╗
// ║          Add AP Opcode           ║
// ╚══════════════════════════════════╝

type addApOpcodeFixture struct {
	expectedSum qm31Literal
}

func newAddApOpcodeFixture(expectedSum qm31Literal) componentFixture {
	return &addApOpcodeFixture{expectedSum: expectedSum}
}

func (f *addApOpcodeFixture) Name() string {
	return "add_ap_opcode"
}

func (f *addApOpcodeFixture) Build(ctx componentContext) componentUnderTest {
	verifyInstruction := ctx.qm31Chip.DummyInteractionElements(7)
	memoryAddress := ctx.qm31Chip.DummyInteractionElements(2)
	memoryIdToBig := ctx.qm31Chip.DummyInteractionElements(29)
	rangeCheck19 := ctx.qm31Chip.DummyInteractionElements(1)
	rangeCheck8 := ctx.qm31Chip.DummyInteractionElements(1)
	opcodes := ctx.qm31Chip.DummyInteractionElements(3)

	claim := cairo_components.AddApOpcodeClaim{LogSize: 3}
	interactionClaim := cairo_components.AddApOpcodeInteractionClaim{ClaimedSum: qm31One.ToQM31()}

	return cairo_components.NewAddApOpcode(
		ctx.qm31Chip,
		verifyInstruction,
		memoryAddress,
		memoryIdToBig,
		rangeCheck19,
		rangeCheck8,
		opcodes,
		claim,
		interactionClaim,
	)
}

func (f *addApOpcodeFixture) SampledValues(ctx componentContext) ([][]m31.QM31, [][]m31.QM31, [][]m31.QM31) {
	preprocessed := make([][]m31.QM31, len(cairo_components.PreprocessedColumns))

	trace := make([][]m31.QM31, 15)
	for i := range trace {
		trace[i] = []m31.QM31{qm31One.ToQM31()}
	}

	interaction := make([][]m31.QM31, 16)
	for i := 0; i < 12; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31()}
	}
	for i := 12; i < 16; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31(), qm31One.ToQM31()}
	}

	return preprocessed, trace, interaction
}

func (f *addApOpcodeFixture) ExpectedSum() qm31Literal {
	return f.expectedSum
}

// ╔══════════════════════════════════╗
// ║        Add Small Opcode          ║
// ╚══════════════════════════════════╝

type addSmallOpcodeFixture struct {
	expectedSum qm31Literal
}

func newAddSmallOpcodeFixture(expectedSum qm31Literal) componentFixture {
	return &addSmallOpcodeFixture{expectedSum: expectedSum}
}

func (f *addSmallOpcodeFixture) Name() string {
	return "add_opcode_small"
}

func (f *addSmallOpcodeFixture) Build(ctx componentContext) componentUnderTest {
	verifyInstruction := ctx.qm31Chip.DummyInteractionElements(7)
	memoryAddress := ctx.qm31Chip.DummyInteractionElements(2)
	memoryIdToBig := ctx.qm31Chip.DummyInteractionElements(29)
	opcodes := ctx.qm31Chip.DummyInteractionElements(3)

	claim := cairo_components.AddSmallOpcodeClaim{LogSize: 3}
	interactionClaim := cairo_components.AddSmallOpcodeInteractionClaim{ClaimedSum: qm31One.ToQM31()}

	return cairo_components.NewAddSmallOpcode(
		ctx.qm31Chip,
		verifyInstruction,
		memoryAddress,
		memoryIdToBig,
		opcodes,
		claim,
		interactionClaim,
	)
}

func (f *addSmallOpcodeFixture) SampledValues(ctx componentContext) ([][]m31.QM31, [][]m31.QM31, [][]m31.QM31) {
	preprocessed := make([][]m31.QM31, len(cairo_components.PreprocessedColumns))

	trace := make([][]m31.QM31, 33)
	for i := range trace {
		trace[i] = []m31.QM31{qm31One.ToQM31()}
	}

	interaction := make([][]m31.QM31, 20)
	for i := 0; i < 16; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31()}
	}
	for i := 16; i < 20; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31(), qm31One.ToQM31()}
	}

	return preprocessed, trace, interaction
}

func (f *addSmallOpcodeFixture) ExpectedSum() qm31Literal {
	return f.expectedSum
}

// ╔══════════════════════════════════╗
// ║      Mul Small Opcode            ║
// ╚══════════════════════════════════╝

type mulSmallOpcodeFixture struct {
	expectedSum qm31Literal
}

func newMulSmallOpcodeFixture(expectedSum qm31Literal) componentFixture {
	return &mulSmallOpcodeFixture{expectedSum: expectedSum}
}

func (f *mulSmallOpcodeFixture) Name() string {
	return "mul_opcode_small"
}

func (f *mulSmallOpcodeFixture) Build(ctx componentContext) componentUnderTest {
	verifyInstruction := ctx.qm31Chip.DummyInteractionElements(7)
	memoryAddress := ctx.qm31Chip.DummyInteractionElements(2)
	memoryIdToBig := ctx.qm31Chip.DummyInteractionElements(29)
	rangeCheck11 := ctx.qm31Chip.DummyInteractionElements(1)
	opcodes := ctx.qm31Chip.DummyInteractionElements(3)

	claim := cairo_components.MulSmallOpcodeClaim{LogSize: 3}
	interactionClaim := cairo_components.MulSmallOpcodeInteractionClaim{ClaimedSum: qm31One.ToQM31()}

	return cairo_components.NewMulSmallOpcode(
		ctx.qm31Chip,
		verifyInstruction,
		memoryAddress,
		memoryIdToBig,
		rangeCheck11,
		opcodes,
		claim,
		interactionClaim,
	)
}

func (f *mulSmallOpcodeFixture) SampledValues(ctx componentContext) ([][]m31.QM31, [][]m31.QM31, [][]m31.QM31) {
	preprocessed := make([][]m31.QM31, len(cairo_components.PreprocessedColumns))

	trace := make([][]m31.QM31, 37)
	for i := range trace {
		trace[i] = []m31.QM31{qm31One.ToQM31()}
	}

	interaction := make([][]m31.QM31, 24)
	for i := 0; i < 20; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31()}
	}
	for i := 20; i < 24; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31(), qm31One.ToQM31()}
	}

	return preprocessed, trace, interaction
}

func (f *mulSmallOpcodeFixture) ExpectedSum() qm31Literal {
	return f.expectedSum
}

// ╔══════════════════════════════════╗
// ║          Mul Opcode              ║
// ╚══════════════════════════════════╝

type mulOpcodeFixture struct {
	expectedSum qm31Literal
}

func newMulOpcodeFixture(expectedSum qm31Literal) componentFixture {
	return &mulOpcodeFixture{expectedSum: expectedSum}
}

func (f *mulOpcodeFixture) Name() string {
	return "mul_opcode"
}

func (f *mulOpcodeFixture) Build(ctx componentContext) componentUnderTest {
	verifyInstruction := ctx.qm31Chip.DummyInteractionElements(7)
	memoryAddress := ctx.qm31Chip.DummyInteractionElements(2)
	memoryIdToBig := ctx.qm31Chip.DummyInteractionElements(29)
	rangeCheck19 := ctx.qm31Chip.DummyInteractionElements(1)
	opcodes := ctx.qm31Chip.DummyInteractionElements(3)

	claim := cairo_components.MulOpcodeClaim{LogSize: 3}
	interactionClaim := cairo_components.MulOpcodeInteractionClaim{ClaimedSum: qm31One.ToQM31()}

	return cairo_components.NewMulOpcode(
		ctx.qm31Chip,
		verifyInstruction,
		memoryAddress,
		memoryIdToBig,
		rangeCheck19,
		opcodes,
		claim,
		interactionClaim,
	)
}

func (f *mulOpcodeFixture) SampledValues(ctx componentContext) ([][]m31.QM31, [][]m31.QM31, [][]m31.QM31) {
	preprocessed := make([][]m31.QM31, len(cairo_components.PreprocessedColumns))

	trace := make([][]m31.QM31, 130)
	for i := range trace {
		trace[i] = []m31.QM31{qm31One.ToQM31()}
	}

	interaction := make([][]m31.QM31, 76)
	for i := 0; i < 72; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31()}
	}
	for i := 72; i < 76; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31(), qm31One.ToQM31()}
	}

	return preprocessed, trace, interaction
}

func (f *mulOpcodeFixture) ExpectedSum() qm31Literal {
	return f.expectedSum
}

// ╔══════════════════════════════════╗
// ║         QM31 Opcode              ║
// ╚══════════════════════════════════╝

type qm31OpcodeFixture struct {
	expectedSum qm31Literal
}

func newQm31OpcodeFixture(expectedSum qm31Literal) componentFixture {
	return &qm31OpcodeFixture{expectedSum: expectedSum}
}

func (f *qm31OpcodeFixture) Name() string {
	return "qm31_opcode"
}

func (f *qm31OpcodeFixture) Build(ctx componentContext) componentUnderTest {
	verifyInstruction := ctx.qm31Chip.DummyInteractionElements(7)
	memoryAddress := ctx.qm31Chip.DummyInteractionElements(2)
	memoryIdToBig := ctx.qm31Chip.DummyInteractionElements(29)
	rangeCheck4444 := ctx.qm31Chip.DummyInteractionElements(4)
	opcodes := ctx.qm31Chip.DummyInteractionElements(3)

	claim := cairo_components.Qm31OpcodeClaim{LogSize: 3}
	interactionClaim := cairo_components.Qm31OpcodeInteractionClaim{ClaimedSum: qm31One.ToQM31()}

	return cairo_components.NewQm31Opcode(
		ctx.qm31Chip,
		verifyInstruction,
		memoryAddress,
		memoryIdToBig,
		rangeCheck4444,
		opcodes,
		claim,
		interactionClaim,
	)
}

func (f *qm31OpcodeFixture) SampledValues(ctx componentContext) ([][]m31.QM31, [][]m31.QM31, [][]m31.QM31) {
	preprocessed := make([][]m31.QM31, len(cairo_components.PreprocessedColumns))

	trace := make([][]m31.QM31, 73)
	for i := range trace {
		trace[i] = []m31.QM31{qm31One.ToQM31()}
	}

	interaction := make([][]m31.QM31, 24)
	for i := 0; i < 20; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31()}
	}
	for i := 20; i < 24; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31(), qm31One.ToQM31()}
	}

	return preprocessed, trace, interaction
}

func (f *qm31OpcodeFixture) ExpectedSum() qm31Literal {
	return f.expectedSum
}

// ╔══════════════════════════════════╗
// ║        Add Mod Builtin           ║
// ╚══════════════════════════════════╝

type addModBuiltinFixture struct {
	expectedSum qm31Literal
}

func newAddModBuiltinFixture(expectedSum qm31Literal) componentFixture {
	return &addModBuiltinFixture{expectedSum: expectedSum}
}

func (f *addModBuiltinFixture) Name() string {
	return "add_mod_builtin"
}

func (f *addModBuiltinFixture) Build(ctx componentContext) componentUnderTest {
	memoryAddress := ctx.qm31Chip.DummyInteractionElements(2)
	memoryIdToBig := ctx.qm31Chip.DummyInteractionElements(29)

	claim := cairo_components.AddModBuiltinClaim{
		LogSize:                   4,
		AddModBuiltinSegmentStart: 3,
	}
	interactionClaim := cairo_components.AddModBuiltinInteractionClaim{
		ClaimedSum: qm31One.ToQM31(),
	}

	return cairo_components.NewAddModBuiltin(
		ctx.qm31Chip,
		memoryAddress,
		memoryIdToBig,
		claim,
		interactionClaim,
	)
}

func (f *addModBuiltinFixture) SampledValues(ctx componentContext) ([][]m31.QM31, [][]m31.QM31, [][]m31.QM31) {
	preprocessed := make([][]m31.QM31, len(cairo_components.PreprocessedColumns))

	seqColumn := cairo_components.NewPreprocessedColumnSeq(uints.NewU8(4))
	index := locatePreprocessedColumnIndex(ctx.api, seqColumn)
	preprocessed[index] = []m31.QM31{qm31One.ToQM31()}

	trace := make([][]m31.QM31, 251)
	for i := range trace {
		trace[i] = []m31.QM31{qm31One.ToQM31()}
	}

	interaction := make([][]m31.QM31, 108)
	for i := 0; i < 104; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31()}
	}
	for i := 104; i < 108; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31(), qm31One.ToQM31()}
	}

	return preprocessed, trace, interaction
}

func (f *addModBuiltinFixture) ExpectedSum() qm31Literal {
	return f.expectedSum
}

// ╔══════════════════════════════════╗
// ║        Bitwise Builtin           ║
// ╚══════════════════════════════════╝

type bitwiseBuiltinFixture struct {
	expectedSum qm31Literal
}

func newBitwiseBuiltinFixture(expectedSum qm31Literal) componentFixture {
	return &bitwiseBuiltinFixture{expectedSum: expectedSum}
}

func (f *bitwiseBuiltinFixture) Name() string {
	return "bitwise_builtin"
}

func (f *bitwiseBuiltinFixture) Build(ctx componentContext) componentUnderTest {
	memoryAddress := ctx.qm31Chip.DummyInteractionElements(2)
	memoryIdToBig := ctx.qm31Chip.DummyInteractionElements(29)
	verifyBitwise := ctx.qm31Chip.DummyInteractionElements(3)

	claim := cairo_components.BitwiseBuiltinClaim{
		LogSize:                    4,
		BitwiseBuiltinSegmentStart: 3,
	}
	interactionClaim := cairo_components.BitwiseBuiltinInteractionClaim{
		ClaimedSum: qm31One.ToQM31(),
	}

	return cairo_components.NewBitwiseBuiltin(
		ctx.qm31Chip,
		memoryAddress,
		memoryIdToBig,
		verifyBitwise,
		claim,
		interactionClaim,
	)
}

func (f *bitwiseBuiltinFixture) SampledValues(ctx componentContext) ([][]m31.QM31, [][]m31.QM31, [][]m31.QM31) {
	preprocessed := make([][]m31.QM31, len(cairo_components.PreprocessedColumns))

	seqColumn := cairo_components.NewPreprocessedColumnSeq(uints.NewU8(4))
	index := locatePreprocessedColumnIndex(ctx.api, seqColumn)
	preprocessed[index] = []m31.QM31{qm31One.ToQM31()}

	trace := make([][]m31.QM31, 89)
	for i := range trace {
		trace[i] = []m31.QM31{qm31One.ToQM31()}
	}

	interaction := make([][]m31.QM31, 76)
	for i := 0; i < 72; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31()}
	}
	for i := 72; i < 76; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31(), qm31One.ToQM31()}
	}

	return preprocessed, trace, interaction
}

func (f *bitwiseBuiltinFixture) ExpectedSum() qm31Literal {
	return f.expectedSum
}

// ╔══════════════════════════════════╗
// ║        Mul Mod Builtin           ║
// ╚══════════════════════════════════╝

type mulModBuiltinFixture struct {
	expectedSum qm31Literal
}

func newMulModBuiltinFixture(expectedSum qm31Literal) componentFixture {
	return &mulModBuiltinFixture{expectedSum: expectedSum}
}

func (f *mulModBuiltinFixture) Name() string {
	return "mul_mod_builtin"
}

func (f *mulModBuiltinFixture) Build(ctx componentContext) componentUnderTest {
	memoryAddress := ctx.qm31Chip.DummyInteractionElements(2)
	memoryIdToBig := ctx.qm31Chip.DummyInteractionElements(29)
	rangeCheck12 := ctx.qm31Chip.DummyInteractionElements(1)
	rangeCheck3 := ctx.qm31Chip.DummyInteractionElements(4)
	rangeCheck18 := ctx.qm31Chip.DummyInteractionElements(1)

	claim := cairo_components.MulModBuiltinClaim{
		LogSize:                   4,
		MulModBuiltinSegmentStart: 3,
	}
	interactionClaim := cairo_components.MulModBuiltinInteractionClaim{
		ClaimedSum: qm31One.ToQM31(),
	}

	return cairo_components.NewMulModBuiltin(
		ctx.qm31Chip,
		memoryAddress,
		memoryIdToBig,
		rangeCheck12,
		rangeCheck3,
		rangeCheck18,
		claim,
		interactionClaim,
	)
}

func (f *mulModBuiltinFixture) SampledValues(ctx componentContext) ([][]m31.QM31, [][]m31.QM31, [][]m31.QM31) {
	preprocessed := make([][]m31.QM31, len(cairo_components.PreprocessedColumns))

	seqColumn := cairo_components.NewPreprocessedColumnSeq(uints.NewU8(4))
	index := locatePreprocessedColumnIndex(ctx.api, seqColumn)
	preprocessed[index] = []m31.QM31{qm31One.ToQM31()}

	trace := make([][]m31.QM31, 410)
	for i := range trace {
		trace[i] = []m31.QM31{qm31One.ToQM31()}
	}

	interaction := make([][]m31.QM31, 376)
	for i := 0; i < 372; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31()}
	}
	for i := 372; i < 376; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31(), qm31One.ToQM31()}
	}

	return preprocessed, trace, interaction
}

func (f *mulModBuiltinFixture) ExpectedSum() qm31Literal {
	return f.expectedSum
}

// ╔══════════════════════════════════╗
// ║       Assert Eq Opcode           ║
// ╚══════════════════════════════════╝

type assertEqOpcodeFixture struct {
	expectedSum qm31Literal
}

func newAssertEqOpcodeFixture(expectedSum qm31Literal) componentFixture {
	return &assertEqOpcodeFixture{expectedSum: expectedSum}
}

func (f *assertEqOpcodeFixture) Name() string {
	return "assert_eq_opcode"
}

func (f *assertEqOpcodeFixture) Build(ctx componentContext) componentUnderTest {
	verifyInstruction := ctx.qm31Chip.DummyInteractionElements(7)
	memoryAddress := ctx.qm31Chip.DummyInteractionElements(2)
	opcodes := ctx.qm31Chip.DummyInteractionElements(3)

	claim := cairo_components.AssertEqOpcodeClaim{LogSize: 3}
	interactionClaim := cairo_components.AssertEqOpcodeInteractionClaim{
		ClaimedSum: qm31One.ToQM31(),
	}

	return cairo_components.NewAssertEqOpcode(
		ctx.qm31Chip,
		verifyInstruction,
		memoryAddress,
		opcodes,
		claim,
		interactionClaim,
	)
}

func (f *assertEqOpcodeFixture) SampledValues(ctx componentContext) ([][]m31.QM31, [][]m31.QM31, [][]m31.QM31) {
	preprocessed := make([][]m31.QM31, len(cairo_components.PreprocessedColumns))

	trace := make([][]m31.QM31, 12)
	for i := range trace {
		trace[i] = []m31.QM31{qm31One.ToQM31()}
	}

	interaction := make([][]m31.QM31, 12)
	for i := 0; i < 8; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31()}
	}
	for i := 8; i < 12; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31(), qm31One.ToQM31()}
	}

	return preprocessed, trace, interaction
}

func (f *assertEqOpcodeFixture) ExpectedSum() qm31Literal {
	return f.expectedSum
}

// ╔══════════════════════════════════╗
// ║ Assert Eq Double Deref           ║
// ╚══════════════════════════════════╝

type assertEqDoubleDerefOpcodeFixture struct {
	expectedSum qm31Literal
}

func newAssertEqDoubleDerefOpcodeFixture(expectedSum qm31Literal) componentFixture {
	return &assertEqDoubleDerefOpcodeFixture{expectedSum: expectedSum}
}

func (f *assertEqDoubleDerefOpcodeFixture) Name() string {
	return "assert_eq_opcode_double_deref"
}

func (f *assertEqDoubleDerefOpcodeFixture) Build(ctx componentContext) componentUnderTest {
	verifyInstruction := ctx.qm31Chip.DummyInteractionElements(7)
	memoryAddress := ctx.qm31Chip.DummyInteractionElements(2)
	memoryIdToBig := ctx.qm31Chip.DummyInteractionElements(29)
	opcodes := ctx.qm31Chip.DummyInteractionElements(3)

	claim := cairo_components.AssertEqDoubleDerefOpcodeClaim{LogSize: 3}
	interactionClaim := cairo_components.AssertEqDoubleDerefOpcodeInteractionClaim{
		ClaimedSum: qm31One.ToQM31(),
	}

	return cairo_components.NewAssertEqDoubleDerefOpcode(
		ctx.qm31Chip,
		verifyInstruction,
		memoryAddress,
		memoryIdToBig,
		opcodes,
		claim,
		interactionClaim,
	)
}

func (f *assertEqDoubleDerefOpcodeFixture) SampledValues(ctx componentContext) ([][]m31.QM31, [][]m31.QM31, [][]m31.QM31) {
	preprocessed := make([][]m31.QM31, len(cairo_components.PreprocessedColumns))

	trace := make([][]m31.QM31, 17)
	for i := range trace {
		trace[i] = []m31.QM31{qm31One.ToQM31()}
	}

	interaction := make([][]m31.QM31, 16)
	for i := 0; i < 12; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31()}
	}
	for i := 12; i < 16; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31(), qm31One.ToQM31()}
	}

	return preprocessed, trace, interaction
}

func (f *assertEqDoubleDerefOpcodeFixture) ExpectedSum() qm31Literal {
	return f.expectedSum
}

// ╔══════════════════════════════════╗
// ║     Assert Eq Imm Opcode         ║
// ╚══════════════════════════════════╝

type assertEqImmOpcodeFixture struct {
	expectedSum qm31Literal
}

func newAssertEqImmOpcodeFixture(expectedSum qm31Literal) componentFixture {
	return &assertEqImmOpcodeFixture{expectedSum: expectedSum}
}

func (f *assertEqImmOpcodeFixture) Name() string {
	return "assert_eq_opcode_imm"
}

func (f *assertEqImmOpcodeFixture) Build(ctx componentContext) componentUnderTest {
	verifyInstruction := ctx.qm31Chip.DummyInteractionElements(7)
	memoryAddress := ctx.qm31Chip.DummyInteractionElements(2)
	opcodes := ctx.qm31Chip.DummyInteractionElements(3)

	claim := cairo_components.AssertEqImmOpcodeClaim{LogSize: 3}
	interactionClaim := cairo_components.AssertEqImmOpcodeInteractionClaim{
		ClaimedSum: qm31One.ToQM31(),
	}

	return cairo_components.NewAssertEqImmOpcode(
		ctx.qm31Chip,
		verifyInstruction,
		memoryAddress,
		opcodes,
		claim,
		interactionClaim,
	)
}

func (f *assertEqImmOpcodeFixture) SampledValues(ctx componentContext) ([][]m31.QM31, [][]m31.QM31, [][]m31.QM31) {
	preprocessed := make([][]m31.QM31, len(cairo_components.PreprocessedColumns))

	trace := make([][]m31.QM31, 9)
	for i := range trace {
		trace[i] = []m31.QM31{qm31One.ToQM31()}
	}

	interaction := make([][]m31.QM31, 12)
	for i := 0; i < 8; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31()}
	}
	for i := 8; i < 12; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31(), qm31One.ToQM31()}
	}

	return preprocessed, trace, interaction
}

func (f *assertEqImmOpcodeFixture) ExpectedSum() qm31Literal {
	return f.expectedSum
}

// ╔══════════════════════════════════╗
// ║           Ret Opcode             ║
// ╚══════════════════════════════════╝

type retOpcodeFixture struct {
	expectedSum qm31Literal
}

func newRetOpcodeFixture(expectedSum qm31Literal) componentFixture {
	return &retOpcodeFixture{expectedSum: expectedSum}
}

func (f *retOpcodeFixture) Name() string {
	return "ret_opcode"
}

func (f *retOpcodeFixture) Build(ctx componentContext) componentUnderTest {
	verifyInstruction := ctx.qm31Chip.DummyInteractionElements(7)
	memoryAddress := ctx.qm31Chip.DummyInteractionElements(2)
	memoryIdToBig := ctx.qm31Chip.DummyInteractionElements(29)
	opcodes := ctx.qm31Chip.DummyInteractionElements(3)

	claim := cairo_components.RetOpcodeClaim{LogSize: 3}
	interactionClaim := cairo_components.RetOpcodeInteractionClaim{
		ClaimedSum: qm31One.ToQM31(),
	}

	return cairo_components.NewRetOpcode(
		ctx.qm31Chip,
		verifyInstruction,
		memoryAddress,
		memoryIdToBig,
		opcodes,
		claim,
		interactionClaim,
	)
}

func (f *retOpcodeFixture) SampledValues(ctx componentContext) ([][]m31.QM31, [][]m31.QM31, [][]m31.QM31) {
	preprocessed := make([][]m31.QM31, len(cairo_components.PreprocessedColumns))

	trace := make([][]m31.QM31, 12)
	for i := range trace {
		trace[i] = []m31.QM31{qm31One.ToQM31()}
	}

	interaction := make([][]m31.QM31, 16)
	for i := 0; i < 12; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31()}
	}
	for i := 12; i < 16; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31(), qm31One.ToQM31()}
	}

	return preprocessed, trace, interaction
}

func (f *retOpcodeFixture) ExpectedSum() qm31Literal {
	return f.expectedSum
}

// ╔══════════════════════════════════╗
// ║            Call Opcode           ║
// ╚══════════════════════════════════╝

type callOpcodeFixture struct {
	expectedSum qm31Literal
}

func newCallOpcodeFixture(expectedSum qm31Literal) componentFixture {
	return &callOpcodeFixture{expectedSum: expectedSum}
}

func (f *callOpcodeFixture) Name() string {
	return "call_opcode"
}

func (f *callOpcodeFixture) Build(ctx componentContext) componentUnderTest {
	verifyInstruction := ctx.qm31Chip.DummyInteractionElements(7)
	memoryAddress := ctx.qm31Chip.DummyInteractionElements(2)
	memoryIdToBig := ctx.qm31Chip.DummyInteractionElements(29)
	opcodes := ctx.qm31Chip.DummyInteractionElements(3)

	claim := cairo_components.CallOpcodeClaim{LogSize: 3}
	interactionClaim := cairo_components.CallOpcodeInteractionClaim{
		ClaimedSum: qm31One.ToQM31(),
	}

	return cairo_components.NewCallOpcode(
		ctx.qm31Chip,
		verifyInstruction,
		memoryAddress,
		memoryIdToBig,
		opcodes,
		claim,
		interactionClaim,
	)
}

func (f *callOpcodeFixture) SampledValues(ctx componentContext) ([][]m31.QM31, [][]m31.QM31, [][]m31.QM31) {
	preprocessed := make([][]m31.QM31, len(cairo_components.PreprocessedColumns))

	trace := make([][]m31.QM31, 19)
	for i := range trace {
		trace[i] = []m31.QM31{qm31One.ToQM31()}
	}

	interaction := make([][]m31.QM31, 20)
	for i := 0; i < 16; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31()}
	}
	for i := 16; i < 20; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31(), qm31One.ToQM31()}
	}

	return preprocessed, trace, interaction
}

func (f *callOpcodeFixture) ExpectedSum() qm31Literal {
	return f.expectedSum
}

// ╔══════════════════════════════════╗
// ║       Call Rel Imm Opcode Fixture║
// ╚══════════════════════════════════╝

type callRelImmOpcodeFixture struct {
	expectedSum qm31Literal
}

func newCallRelImmOpcodeFixture(expectedSum qm31Literal) componentFixture {
	return &callRelImmOpcodeFixture{expectedSum: expectedSum}
}

func (f *callRelImmOpcodeFixture) Name() string {
	return "call_opcode_rel_imm"
}

func (f *callRelImmOpcodeFixture) Build(ctx componentContext) componentUnderTest {
	verifyInstruction := ctx.qm31Chip.DummyInteractionElements(7)
	memoryAddress := ctx.qm31Chip.DummyInteractionElements(2)
	memoryIdToBig := ctx.qm31Chip.DummyInteractionElements(29)
	opcodes := ctx.qm31Chip.DummyInteractionElements(3)

	claim := cairo_components.CallRelImmOpcodeClaim{LogSize: 3}
	interactionClaim := cairo_components.CallRelImmOpcodeInteractionClaim{
		ClaimedSum: qm31One.ToQM31(),
	}

	return cairo_components.NewCallRelImmOpcode(
		ctx.qm31Chip,
		verifyInstruction,
		memoryAddress,
		memoryIdToBig,
		opcodes,
		claim,
		interactionClaim,
	)
}

func (f *callRelImmOpcodeFixture) SampledValues(ctx componentContext) ([][]m31.QM31, [][]m31.QM31, [][]m31.QM31) {
	preprocessed := make([][]m31.QM31, len(cairo_components.PreprocessedColumns))

	trace := make([][]m31.QM31, 18)
	for i := range trace {
		trace[i] = []m31.QM31{qm31One.ToQM31()}
	}

	interaction := make([][]m31.QM31, 20)
	for i := 0; i < 16; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31()}
	}
	for i := 16; i < 20; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31(), qm31One.ToQM31()}
	}

	return preprocessed, trace, interaction
}

func (f *callRelImmOpcodeFixture) ExpectedSum() qm31Literal {
	return f.expectedSum
}

// ╔══════════════════════════════════╗
// ║           Jump Opcode            ║
// ╚══════════════════════════════════╝

type jumpOpcodeFixture struct {
	expectedSum qm31Literal
}

func newJumpOpcodeFixture(expectedSum qm31Literal) componentFixture {
	return &jumpOpcodeFixture{expectedSum: expectedSum}
}

func (f *jumpOpcodeFixture) Name() string {
	return "jump_opcode"
}

func (f *jumpOpcodeFixture) Build(ctx componentContext) componentUnderTest {
	verifyInstruction := ctx.qm31Chip.DummyInteractionElements(7)
	memoryAddress := ctx.qm31Chip.DummyInteractionElements(2)
	memoryIdToBig := ctx.qm31Chip.DummyInteractionElements(29)
	opcodes := ctx.qm31Chip.DummyInteractionElements(3)

	claim := cairo_components.JumpOpcodeClaim{LogSize: 3}
	interactionClaim := cairo_components.JumpOpcodeInteractionClaim{
		ClaimedSum: qm31One.ToQM31(),
	}

	return cairo_components.NewJumpOpcode(
		ctx.qm31Chip,
		verifyInstruction,
		memoryAddress,
		memoryIdToBig,
		opcodes,
		claim,
		interactionClaim,
	)
}

func (f *jumpOpcodeFixture) SampledValues(ctx componentContext) ([][]m31.QM31, [][]m31.QM31, [][]m31.QM31) {
	preprocessed := make([][]m31.QM31, len(cairo_components.PreprocessedColumns))

	trace := make([][]m31.QM31, 13)
	for i := range trace {
		trace[i] = []m31.QM31{qm31One.ToQM31()}
	}

	interaction := make([][]m31.QM31, 12)
	for i := 0; i < 8; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31()}
	}
	for i := 8; i < 12; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31(), qm31One.ToQM31()}
	}

	return preprocessed, trace, interaction
}

func (f *jumpOpcodeFixture) ExpectedSum() qm31Literal {
	return f.expectedSum
}

// ╔══════════════════════════════════╗
// ║       Jump Rel Opcode            ║
// ╚══════════════════════════════════╝

type jumpRelOpcodeFixture struct {
	expectedSum qm31Literal
}

func newJumpRelOpcodeFixture(expectedSum qm31Literal) componentFixture {
	return &jumpRelOpcodeFixture{expectedSum: expectedSum}
}

func (f *jumpRelOpcodeFixture) Name() string {
	return "jump_opcode_rel"
}

func (f *jumpRelOpcodeFixture) Build(ctx componentContext) componentUnderTest {
	verifyInstruction := ctx.qm31Chip.DummyInteractionElements(7)
	memoryAddress := ctx.qm31Chip.DummyInteractionElements(2)
	memoryIdToBig := ctx.qm31Chip.DummyInteractionElements(29)
	opcodes := ctx.qm31Chip.DummyInteractionElements(3)

	claim := cairo_components.JumpRelOpcodeClaim{LogSize: 3}
	interactionClaim := cairo_components.JumpRelOpcodeInteractionClaim{
		ClaimedSum: qm31One.ToQM31(),
	}

	return cairo_components.NewJumpRelOpcode(
		ctx.qm31Chip,
		verifyInstruction,
		memoryAddress,
		memoryIdToBig,
		opcodes,
		claim,
		interactionClaim,
	)
}

func (f *jumpRelOpcodeFixture) SampledValues(ctx componentContext) ([][]m31.QM31, [][]m31.QM31, [][]m31.QM31) {
	preprocessed := make([][]m31.QM31, len(cairo_components.PreprocessedColumns))

	trace := make([][]m31.QM31, 15)
	for i := range trace {
		trace[i] = []m31.QM31{qm31One.ToQM31()}
	}

	interaction := make([][]m31.QM31, 12)
	for i := 0; i < 8; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31()}
	}
	for i := 8; i < 12; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31(), qm31One.ToQM31()}
	}

	return preprocessed, trace, interaction
}

func (f *jumpRelOpcodeFixture) ExpectedSum() qm31Literal {
	return f.expectedSum
}

// ╔══════════════════════════════════╗
// ║     Jump Rel Imm Opcode          ║
// ╚══════════════════════════════════╝

type jumpRelImmOpcodeFixture struct {
	expectedSum qm31Literal
}

func newJumpRelImmOpcodeFixture(expectedSum qm31Literal) componentFixture {
	return &jumpRelImmOpcodeFixture{expectedSum: expectedSum}
}

func (f *jumpRelImmOpcodeFixture) Name() string {
	return "jump_opcode_rel_imm"
}

func (f *jumpRelImmOpcodeFixture) Build(ctx componentContext) componentUnderTest {
	verifyInstruction := ctx.qm31Chip.DummyInteractionElements(7)
	memoryAddress := ctx.qm31Chip.DummyInteractionElements(2)
	memoryIdToBig := ctx.qm31Chip.DummyInteractionElements(29)
	opcodes := ctx.qm31Chip.DummyInteractionElements(3)

	claim := cairo_components.JumpRelImmOpcodeClaim{LogSize: 3}
	interactionClaim := cairo_components.JumpRelImmOpcodeInteractionClaim{
		ClaimedSum: qm31One.ToQM31(),
	}

	return cairo_components.NewJumpRelImmOpcode(
		ctx.qm31Chip,
		verifyInstruction,
		memoryAddress,
		memoryIdToBig,
		opcodes,
		claim,
		interactionClaim,
	)
}

func (f *jumpRelImmOpcodeFixture) SampledValues(ctx componentContext) ([][]m31.QM31, [][]m31.QM31, [][]m31.QM31) {
	preprocessed := make([][]m31.QM31, len(cairo_components.PreprocessedColumns))

	trace := make([][]m31.QM31, 11)
	for i := range trace {
		trace[i] = []m31.QM31{qm31One.ToQM31()}
	}

	interaction := make([][]m31.QM31, 12)
	for i := 0; i < 8; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31()}
	}
	for i := 8; i < 12; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31(), qm31One.ToQM31()}
	}

	return preprocessed, trace, interaction
}

func (f *jumpRelImmOpcodeFixture) ExpectedSum() qm31Literal {
	return f.expectedSum
}

// ╔══════════════════════════════════╗
// ║  Jump Double Deref Opcode Fixture║
// ╚══════════════════════════════════╝

type jumpDoubleDerefOpcodeFixture struct {
	expectedSum qm31Literal
}

func newJumpDoubleDerefOpcodeFixture(expectedSum qm31Literal) componentFixture {
	return &jumpDoubleDerefOpcodeFixture{expectedSum: expectedSum}
}

func (f *jumpDoubleDerefOpcodeFixture) Name() string {
	return "jump_opcode_double_deref"
}

func (f *jumpDoubleDerefOpcodeFixture) Build(ctx componentContext) componentUnderTest {
	verifyInstruction := ctx.qm31Chip.DummyInteractionElements(7)
	memoryAddress := ctx.qm31Chip.DummyInteractionElements(2)
	memoryIdToBig := ctx.qm31Chip.DummyInteractionElements(29)
	opcodes := ctx.qm31Chip.DummyInteractionElements(3)

	claim := cairo_components.JumpDoubleDerefOpcodeClaim{LogSize: 3}
	interactionClaim := cairo_components.JumpDoubleDerefOpcodeInteractionClaim{
		ClaimedSum: qm31One.ToQM31(),
	}

	return cairo_components.NewJumpDoubleDerefOpcode(
		ctx.qm31Chip,
		verifyInstruction,
		memoryAddress,
		memoryIdToBig,
		opcodes,
		claim,
		interactionClaim,
	)
}

func (f *jumpDoubleDerefOpcodeFixture) SampledValues(ctx componentContext) ([][]m31.QM31, [][]m31.QM31, [][]m31.QM31) {
	preprocessed := make([][]m31.QM31, len(cairo_components.PreprocessedColumns))

	trace := make([][]m31.QM31, 17)
	for i := range trace {
		trace[i] = []m31.QM31{qm31One.ToQM31()}
	}

	interaction := make([][]m31.QM31, 16)
	for i := 0; i < 12; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31()}
	}
	for i := 12; i < 16; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31(), qm31One.ToQM31()}
	}

	return preprocessed, trace, interaction
}

func (f *jumpDoubleDerefOpcodeFixture) ExpectedSum() qm31Literal {
	return f.expectedSum
}

// ╔══════════════════════════════════╗
// ║           JNZ Opcode             ║
// ╚══════════════════════════════════╝

type jnzOpcodeFixture struct {
	expectedSum qm31Literal
}

func newJnzOpcodeFixture(expectedSum qm31Literal) componentFixture {
	return &jnzOpcodeFixture{expectedSum: expectedSum}
}

func (f *jnzOpcodeFixture) Name() string {
	return "jnz_opcode"
}

func (f *jnzOpcodeFixture) Build(ctx componentContext) componentUnderTest {
	verifyInstruction := ctx.qm31Chip.DummyInteractionElements(7)
	memoryAddress := ctx.qm31Chip.DummyInteractionElements(2)
	memoryIdToBig := ctx.qm31Chip.DummyInteractionElements(29)
	opcodes := ctx.qm31Chip.DummyInteractionElements(3)

	claim := cairo_components.JnzOpcodeClaim{LogSize: 3}
	interactionClaim := cairo_components.JnzOpcodeInteractionClaim{
		ClaimedSum: qm31One.ToQM31(),
	}

	return cairo_components.NewJnzOpcode(
		ctx.qm31Chip,
		verifyInstruction,
		memoryAddress,
		memoryIdToBig,
		opcodes,
		claim,
		interactionClaim,
	)
}

func (f *jnzOpcodeFixture) SampledValues(ctx componentContext) ([][]m31.QM31, [][]m31.QM31, [][]m31.QM31) {
	preprocessed := make([][]m31.QM31, len(cairo_components.PreprocessedColumns))

	trace := make([][]m31.QM31, 37)
	for i := range trace {
		trace[i] = []m31.QM31{qm31One.ToQM31()}
	}

	interaction := make([][]m31.QM31, 12)
	for i := 0; i < 8; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31()}
	}
	for i := 8; i < 12; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31(), qm31One.ToQM31()}
	}

	return preprocessed, trace, interaction
}

func (f *jnzOpcodeFixture) ExpectedSum() qm31Literal {
	return f.expectedSum
}

// ╔══════════════════════════════════╗
// ║        JNZ Taken Opcode          ║
// ╚══════════════════════════════════╝

type jnzTakenOpcodeFixture struct {
	expectedSum qm31Literal
}

func newJnzTakenOpcodeFixture(expectedSum qm31Literal) componentFixture {
	return &jnzTakenOpcodeFixture{expectedSum: expectedSum}
}

func (f *jnzTakenOpcodeFixture) Name() string {
	return "jnz_opcode_taken"
}

func (f *jnzTakenOpcodeFixture) Build(ctx componentContext) componentUnderTest {
	verifyInstruction := ctx.qm31Chip.DummyInteractionElements(7)
	memoryAddress := ctx.qm31Chip.DummyInteractionElements(2)
	memoryIdToBig := ctx.qm31Chip.DummyInteractionElements(29)
	opcodes := ctx.qm31Chip.DummyInteractionElements(3)

	claim := cairo_components.JnzTakenOpcodeClaim{LogSize: 3}
	interactionClaim := cairo_components.JnzTakenOpcodeInteractionClaim{
		ClaimedSum: qm31One.ToQM31(),
	}

	return cairo_components.NewJnzTakenOpcode(
		ctx.qm31Chip,
		verifyInstruction,
		memoryAddress,
		memoryIdToBig,
		opcodes,
		claim,
		interactionClaim,
	)
}

func (f *jnzTakenOpcodeFixture) SampledValues(ctx componentContext) ([][]m31.QM31, [][]m31.QM31, [][]m31.QM31) {
	preprocessed := make([][]m31.QM31, len(cairo_components.PreprocessedColumns))

	trace := make([][]m31.QM31, 45)
	for i := range trace {
		trace[i] = []m31.QM31{qm31One.ToQM31()}
	}

	interaction := make([][]m31.QM31, 16)
	for i := 0; i < 12; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31()}
	}
	for i := 12; i < 16; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31(), qm31One.ToQM31()}
	}

	return preprocessed, trace, interaction
}

func (f *jnzTakenOpcodeFixture) ExpectedSum() qm31Literal {
	return f.expectedSum
}

// ╔══════════════════════════════════╗
// ║   Memory Id To Big (Small)       ║
// ╚══════════════════════════════════╝

type memoryIdToBigSmallFixture struct {
	expectedSum qm31Literal
}

func newMemoryIdToBigSmallFixture(expectedSum qm31Literal) componentFixture {
	return &memoryIdToBigSmallFixture{expectedSum: expectedSum}
}

func (f *memoryIdToBigSmallFixture) Name() string {
	return "memory_id_to_big_small_component"
}

func (f *memoryIdToBigSmallFixture) Build(ctx componentContext) componentUnderTest {
	memoryIdToBig := ctx.qm31Chip.DummyInteractionElements(29)
	rangeCheck := ctx.qm31Chip.DummyInteractionElements(2)

	claim := cairo_components.MemoryIdToBigSmallClaim{LogSize: 4}
	interactionClaim := cairo_components.MemoryIdToBigSmallInteractionClaim{
		ClaimedSum: qm31One.ToQM31(),
	}

	return cairo_components.NewMemoryIdToBigSmallComponent(
		ctx.qm31Chip,
		memoryIdToBig,
		rangeCheck,
		claim,
		interactionClaim,
	)
}

func (f *memoryIdToBigSmallFixture) SampledValues(ctx componentContext) ([][]m31.QM31, [][]m31.QM31, [][]m31.QM31) {
	preprocessed := make([][]m31.QM31, len(cairo_components.PreprocessedColumns))

	seqColumn := cairo_components.NewPreprocessedColumnSeq(uints.NewU8(4))
	index := locatePreprocessedColumnIndex(ctx.api, seqColumn)
	preprocessed[index] = []m31.QM31{qm31One.ToQM31()}

	trace := make([][]m31.QM31, 9)
	for i := range trace {
		trace[i] = []m31.QM31{qm31One.ToQM31()}
	}

	interaction := make([][]m31.QM31, 20)
	for i := 0; i < 16; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31()}
	}
	for i := 16; i < 20; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31(), qm31One.ToQM31()}
	}

	return preprocessed, trace, interaction
}

func (f *memoryIdToBigSmallFixture) ExpectedSum() qm31Literal {
	return f.expectedSum
}

// ╔══════════════════════════════════╗
// ║    Memory Id To Big (Big)        ║
// ╚══════════════════════════════════╝

type memoryIdToBigBigFixture struct {
	expectedSum qm31Literal
}

func newMemoryIdToBigBigFixture(expectedSum qm31Literal) componentFixture {
	return &memoryIdToBigBigFixture{expectedSum: expectedSum}
}

func (f *memoryIdToBigBigFixture) Name() string {
	return "memory_id_to_big_big_component"
}

func (f *memoryIdToBigBigFixture) Build(ctx componentContext) componentUnderTest {
	memoryIdToBig := ctx.qm31Chip.DummyInteractionElements(29)
	rangeCheck := ctx.qm31Chip.DummyInteractionElements(2)

	claim := cairo_components.MemoryIdToBigBigClaim{
		LogSize: 4,
		Offset:  0,
	}
	interactionClaim := cairo_components.MemoryIdToBigBigInteractionClaim{
		ClaimedSum: qm31One.ToQM31(),
	}

	return cairo_components.NewMemoryIdToBigBigComponent(
		ctx.qm31Chip,
		memoryIdToBig,
		rangeCheck,
		claim,
		interactionClaim,
	)
}

func (f *memoryIdToBigBigFixture) SampledValues(ctx componentContext) ([][]m31.QM31, [][]m31.QM31, [][]m31.QM31) {
	preprocessed := make([][]m31.QM31, len(cairo_components.PreprocessedColumns))

	seqColumn := cairo_components.NewPreprocessedColumnSeq(uints.NewU8(4))
	index := locatePreprocessedColumnIndex(ctx.api, seqColumn)
	preprocessed[index] = []m31.QM31{qm31One.ToQM31()}

	trace := make([][]m31.QM31, 29)
	for i := range trace {
		trace[i] = []m31.QM31{qm31One.ToQM31()}
	}

	interaction := make([][]m31.QM31, 32)
	for i := 0; i < 28; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31()}
	}
	for i := 28; i < 32; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31(), qm31One.ToQM31()}
	}

	return preprocessed, trace, interaction
}

func (f *memoryIdToBigBigFixture) ExpectedSum() qm31Literal {
	return f.expectedSum
}

// ╔══════════════════════════════════╗
// ║     Pedersen Points Table        ║
// ╚══════════════════════════════════╝

type pedersenPointsTableFixture struct {
	expectedSum qm31Literal
}

func newPedersenPointsTableFixture(expectedSum qm31Literal) componentFixture {
	return &pedersenPointsTableFixture{expectedSum: expectedSum}
}

func (f *pedersenPointsTableFixture) Name() string {
	return "pedersen_points_table"
}

func (f *pedersenPointsTableFixture) Build(ctx componentContext) componentUnderTest {
	points := ctx.qm31Chip.DummyInteractionElements(57)

	return cairo_components.NewPedersenPointsTable(
		ctx.qm31Chip,
		points,
		cairo_components.PedersenPointsTableInteractionClaim{ClaimedSum: qm31One.ToQM31()},
	)
}

func (f *pedersenPointsTableFixture) SampledValues(ctx componentContext) ([][]m31.QM31, [][]m31.QM31, [][]m31.QM31) {
	preprocessed := make([][]m31.QM31, len(cairo_components.PreprocessedColumns))

	seqColumn := cairo_components.NewPreprocessedColumnSeq(uints.NewU8(uint8(23)))
	index := locatePreprocessedColumnIndex(ctx.api, seqColumn)
	preprocessed[index] = []m31.QM31{qm31One.ToQM31()}

	for i := 0; i < 56; i++ {
		column := cairo_components.NewPreprocessedColumnPedersenPoints(uints.NewU8(uint8(i)))
		idx := locatePreprocessedColumnIndex(ctx.api, column)
		preprocessed[idx] = []m31.QM31{qm31One.ToQM31()}
	}

	trace := make([][]m31.QM31, 1)
	trace[0] = []m31.QM31{qm31One.ToQM31()}

	interaction := make([][]m31.QM31, 4)
	for i := range interaction {
		interaction[i] = []m31.QM31{qm31One.ToQM31(), qm31One.ToQM31()}
	}

	return preprocessed, trace, interaction
}

func (f *pedersenPointsTableFixture) ExpectedSum() qm31Literal {
	return f.expectedSum
}

// ╔══════════════════════════════════╗
// ║        Partial EC Mul            ║
// ╚══════════════════════════════════╝

type partialEcMulFixture struct {
	expectedSum qm31Literal
}

func newPartialEcMulFixture(expectedSum qm31Literal) componentFixture {
	return &partialEcMulFixture{expectedSum: expectedSum}
}

func (f *partialEcMulFixture) Name() string {
	return "partial_ec_mul"
}

func (f *partialEcMulFixture) Build(ctx componentContext) componentUnderTest {
	claim := cairo_components.PartialEcMulClaim{LogSize: 3}
	interactionClaim := cairo_components.PartialEcMulInteractionClaim{
		ClaimedSum: qm31One.ToQM31(),
	}

	return cairo_components.NewPartialEcMul(
		ctx.qm31Chip,
		ctx.qm31Chip.DummyInteractionElements(57),
		ctx.qm31Chip.DummyInteractionElements(2),
		ctx.qm31Chip.DummyInteractionElements(1),
		ctx.qm31Chip.DummyInteractionElements(73),
		claim,
		interactionClaim,
	)
}

func (f *partialEcMulFixture) SampledValues(ctx componentContext) ([][]m31.QM31, [][]m31.QM31, [][]m31.QM31) {
	preprocessed := make([][]m31.QM31, len(cairo_components.PreprocessedColumns))

	trace := make([][]m31.QM31, 472)
	for i := range trace {
		trace[i] = []m31.QM31{qm31One.ToQM31()}
	}

	interaction := make([][]m31.QM31, 428)
	for i := range interaction {
		if i >= 424 {
			interaction[i] = []m31.QM31{qm31One.ToQM31(), qm31One.ToQM31()}
		} else {
			interaction[i] = []m31.QM31{qm31One.ToQM31()}
		}
	}

	return preprocessed, trace, interaction
}

func (f *partialEcMulFixture) ExpectedSum() qm31Literal {
	return f.expectedSum
}

// ╔══════════════════════════════════╗
// ║        Pedersen Builtin          ║
// ╚══════════════════════════════════╝

type pedersenBuiltinFixture struct {
	expectedSum qm31Literal
}

func newPedersenBuiltinFixture(expectedSum qm31Literal) componentFixture {
	return &pedersenBuiltinFixture{expectedSum: expectedSum}
}

func (f *pedersenBuiltinFixture) Name() string {
	return "pedersen_builtin"
}

func (f *pedersenBuiltinFixture) Build(ctx componentContext) componentUnderTest {
	claim := cairo_components.PedersenBuiltinClaim{
		LogSize:                     4,
		PedersenBuiltinSegmentStart: 3,
	}
	interactionClaim := cairo_components.PedersenBuiltinInteractionClaim{
		ClaimedSum: qm31One.ToQM31(),
	}

	return cairo_components.NewPedersenBuiltin(
		ctx.qm31Chip,
		ctx.qm31Chip.DummyInteractionElements(2),
		ctx.qm31Chip.DummyInteractionElements(2),
		ctx.qm31Chip.DummyInteractionElements(29),
		ctx.qm31Chip.DummyInteractionElements(1),
		ctx.qm31Chip.DummyInteractionElements(73),
		claim,
		interactionClaim,
	)
}

func (f *pedersenBuiltinFixture) SampledValues(ctx componentContext) ([][]m31.QM31, [][]m31.QM31, [][]m31.QM31) {
	preprocessed := make([][]m31.QM31, len(cairo_components.PreprocessedColumns))
	seqColumn := cairo_components.NewPreprocessedColumnSeq(uints.NewU8(4))
	index := locatePreprocessedColumnIndex(ctx.api, seqColumn)
	preprocessed[index] = []m31.QM31{qm31One.ToQM31()}

	trace := make([][]m31.QM31, 351)
	for i := range trace {
		trace[i] = []m31.QM31{qm31One.ToQM31()}
	}

	interaction := make([][]m31.QM31, 40)
	for i := 0; i < 40; i++ {
		if i >= 36 {
			interaction[i] = []m31.QM31{qm31One.ToQM31(), qm31One.ToQM31()}
		} else {
			interaction[i] = []m31.QM31{qm31One.ToQM31()}
		}
	}

	return preprocessed, trace, interaction
}

func (f *pedersenBuiltinFixture) ExpectedSum() qm31Literal {
	return f.expectedSum
}

// ╔══════════════════════════════════╗
// ║      Poseidon Round Keys         ║
// ╚══════════════════════════════════╝

type poseidonRoundKeysFixture struct {
	expectedSum qm31Literal
}

func newPoseidonRoundKeysFixture(expectedSum qm31Literal) componentFixture {
	return &poseidonRoundKeysFixture{expectedSum: expectedSum}
}

func (f *poseidonRoundKeysFixture) Name() string {
	return "poseidon_round_keys"
}

func (f *poseidonRoundKeysFixture) Build(ctx componentContext) componentUnderTest {
	keys := ctx.qm31Chip.DummyInteractionElements(31)

	return cairo_components.NewPoseidonRoundKeys(
		ctx.qm31Chip,
		keys,
		cairo_components.PoseidonRoundKeysInteractionClaim{ClaimedSum: qm31One.ToQM31()},
	)
}

func (f *poseidonRoundKeysFixture) SampledValues(ctx componentContext) ([][]m31.QM31, [][]m31.QM31, [][]m31.QM31) {
	preprocessed := make([][]m31.QM31, len(cairo_components.PreprocessedColumns))

	seqColumn := cairo_components.NewPreprocessedColumnSeq(uints.NewU8(uint8(6)))
	index := locatePreprocessedColumnIndex(ctx.api, seqColumn)
	preprocessed[index] = []m31.QM31{qm31One.ToQM31()}

	for i := 0; i < 30; i++ {
		column := cairo_components.NewPreprocessedColumnPoseidonRoundKeys(uints.NewU8(uint8(i)))
		idx := locatePreprocessedColumnIndex(ctx.api, column)
		preprocessed[idx] = []m31.QM31{qm31One.ToQM31()}
	}

	trace := make([][]m31.QM31, 1)
	trace[0] = []m31.QM31{qm31One.ToQM31()}

	interaction := make([][]m31.QM31, 4)
	for i := range interaction {
		interaction[i] = []m31.QM31{qm31One.ToQM31(), qm31One.ToQM31()}
	}

	return preprocessed, trace, interaction
}

func (f *poseidonRoundKeysFixture) ExpectedSum() qm31Literal {
	return f.expectedSum
}

// ╔══════════════════════════════════╗
// ║  Poseidon 3 Partial Rounds Chain ║
// ╚══════════════════════════════════╝

type poseidon3PartialRoundsChainFixture struct {
	expectedSum qm31Literal
}

func newPoseidon3PartialRoundsChainFixture(expectedSum qm31Literal) componentFixture {
	return &poseidon3PartialRoundsChainFixture{expectedSum: expectedSum}
}

func (f *poseidon3PartialRoundsChainFixture) Name() string {
	return "poseidon_3_partial_rounds_chain"
}

func (f *poseidon3PartialRoundsChainFixture) Build(ctx componentContext) componentUnderTest {
	poseidonRoundKeys := ctx.qm31Chip.DummyInteractionElements(31)
	cube252 := ctx.qm31Chip.DummyInteractionElements(20)
	range4444 := ctx.qm31Chip.DummyInteractionElements(4)
	range44 := ctx.qm31Chip.DummyInteractionElements(2)
	rangeFelt := ctx.qm31Chip.DummyInteractionElements(10)
	partialChain := ctx.qm31Chip.DummyInteractionElements(42)

	claim := cairo_components.Poseidon3PartialRoundsChainClaim{LogSize: 3}
	interactionClaim := cairo_components.Poseidon3PartialRoundsChainInteractionClaim{
		ClaimedSum: qm31One.ToQM31(),
	}

	return cairo_components.NewPoseidon3PartialRoundsChain(
		ctx.qm31Chip,
		poseidonRoundKeys,
		cube252,
		range4444,
		range44,
		rangeFelt,
		partialChain,
		claim,
		interactionClaim,
	)
}

func (f *poseidon3PartialRoundsChainFixture) SampledValues(ctx componentContext) ([][]m31.QM31, [][]m31.QM31, [][]m31.QM31) {
	preprocessed := make([][]m31.QM31, len(cairo_components.PreprocessedColumns))

	trace := make([][]m31.QM31, 169)
	for i := range trace {
		trace[i] = []m31.QM31{qm31One.ToQM31()}
	}

	interaction := make([][]m31.QM31, 36)
	for i := 0; i < 32; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31()}
	}
	for i := 32; i < 36; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31(), qm31One.ToQM31()}
	}

	return preprocessed, trace, interaction
}

func (f *poseidon3PartialRoundsChainFixture) ExpectedSum() qm31Literal {
	return f.expectedSum
}

// ╔══════════════════════════════════╗
// ║            Cube 252              ║
// ╚══════════════════════════════════╝

type cube252Fixture struct {
	expectedSum qm31Literal
}

func newCube252Fixture(expectedSum qm31Literal) componentFixture {
	return &cube252Fixture{expectedSum: expectedSum}
}

func (f *cube252Fixture) Name() string {
	return "cube_252"
}

func (f *cube252Fixture) Build(ctx componentContext) componentUnderTest {
	rangeCheck9 := ctx.qm31Chip.DummyInteractionElements(2)
	rangeCheck19 := ctx.qm31Chip.DummyInteractionElements(1)
	cubeElements := ctx.qm31Chip.DummyInteractionElements(20)

	claim := cairo_components.Cube252Claim{LogSize: 3}
	interactionClaim := cairo_components.Cube252InteractionClaim{
		ClaimedSum: qm31One.ToQM31(),
	}

	return cairo_components.NewCube252(
		ctx.qm31Chip,
		rangeCheck9,
		rangeCheck19,
		cubeElements,
		claim,
		interactionClaim,
	)
}

func (f *cube252Fixture) SampledValues(ctx componentContext) ([][]m31.QM31, [][]m31.QM31, [][]m31.QM31) {
	preprocessed := make([][]m31.QM31, len(cairo_components.PreprocessedColumns))

	trace := make([][]m31.QM31, 141)
	for i := range trace {
		trace[i] = []m31.QM31{qm31One.ToQM31()}
	}

	interaction := make([][]m31.QM31, 200)
	for i := range interaction {
		interaction[i] = []m31.QM31{qm31One.ToQM31()}
	}
	for i := 196; i < 200; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31(), qm31One.ToQM31()}
	}

	return preprocessed, trace, interaction
}

func (f *cube252Fixture) ExpectedSum() qm31Literal {
	return f.expectedSum
}

// ╔══════════════════════════════════╗
// ║     Poseidon Full Round Chain    ║
// ╚══════════════════════════════════╝

type poseidonFullRoundChainFixture struct {
	expectedSum qm31Literal
}

func newPoseidonFullRoundChainFixture(expectedSum qm31Literal) componentFixture {
	return &poseidonFullRoundChainFixture{expectedSum: expectedSum}
}

func (f *poseidonFullRoundChainFixture) Name() string {
	return "poseidon_full_round_chain"
}

func (f *poseidonFullRoundChainFixture) Build(ctx componentContext) componentUnderTest {
	cube252 := ctx.qm31Chip.DummyInteractionElements(20)
	poseidonRoundKeys := ctx.qm31Chip.DummyInteractionElements(31)
	range33333 := ctx.qm31Chip.DummyInteractionElements(5)
	fullChain := ctx.qm31Chip.DummyInteractionElements(32)

	claim := cairo_components.PoseidonFullRoundChainClaim{LogSize: 3}
	interactionClaim := cairo_components.PoseidonFullRoundChainInteractionClaim{
		ClaimedSum: qm31One.ToQM31(),
	}

	return cairo_components.NewPoseidonFullRoundChain(
		ctx.qm31Chip,
		cube252,
		poseidonRoundKeys,
		range33333,
		fullChain,
		claim,
		interactionClaim,
	)
}

func (f *poseidonFullRoundChainFixture) SampledValues(ctx componentContext) ([][]m31.QM31, [][]m31.QM31, [][]m31.QM31) {
	preprocessed := make([][]m31.QM31, len(cairo_components.PreprocessedColumns))

	trace := make([][]m31.QM31, 126)
	for i := range trace {
		trace[i] = []m31.QM31{qm31One.ToQM31()}
	}

	interaction := make([][]m31.QM31, 24)
	for i := 0; i < 20; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31()}
	}
	for i := 20; i < 24; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31(), qm31One.ToQM31()}
	}

	return preprocessed, trace, interaction
}

func (f *poseidonFullRoundChainFixture) ExpectedSum() qm31Literal {
	return f.expectedSum
}

// ╔══════════════════════════════════╗
// ║        Poseidon Builtin          ║
// ╚══════════════════════════════════╝

type poseidonBuiltinFixture struct {
	expectedSum qm31Literal
}

func newPoseidonBuiltinFixture(expectedSum qm31Literal) componentFixture {
	return &poseidonBuiltinFixture{expectedSum: expectedSum}
}

func (f *poseidonBuiltinFixture) Name() string {
	return "poseidon_builtin"
}

func (f *poseidonBuiltinFixture) Build(ctx componentContext) componentUnderTest {
	claim := cairo_components.PoseidonBuiltinClaim{
		LogSize:                     4,
		PoseidonBuiltinSegmentStart: 3,
	}
	interactionClaim := cairo_components.PoseidonBuiltinInteractionClaim{
		ClaimedSum: qm31One.ToQM31(),
	}

	return cairo_components.NewPoseidonBuiltin(
		ctx.qm31Chip,
		ctx.qm31Chip.DummyInteractionElements(2),
		ctx.qm31Chip.DummyInteractionElements(29),
		ctx.qm31Chip.DummyInteractionElements(32),
		ctx.qm31Chip.DummyInteractionElements(10),
		ctx.qm31Chip.DummyInteractionElements(20),
		ctx.qm31Chip.DummyInteractionElements(5),
		ctx.qm31Chip.DummyInteractionElements(4),
		ctx.qm31Chip.DummyInteractionElements(2),
		ctx.qm31Chip.DummyInteractionElements(42),
		claim,
		interactionClaim,
	)
}

func (f *poseidonBuiltinFixture) SampledValues(ctx componentContext) ([][]m31.QM31, [][]m31.QM31, [][]m31.QM31) {
	preprocessed := make([][]m31.QM31, len(cairo_components.PreprocessedColumns))
	seqColumn := cairo_components.NewPreprocessedColumnSeq(uints.NewU8(4))
	index := locatePreprocessedColumnIndex(ctx.api, seqColumn)
	preprocessed[index] = []m31.QM31{qm31One.ToQM31()}

	trace := make([][]m31.QM31, 341)
	for i := range trace {
		trace[i] = []m31.QM31{qm31One.ToQM31()}
	}

	interaction := make([][]m31.QM31, 68)
	for i := 0; i < 68; i++ {
		if i >= 64 {
			interaction[i] = []m31.QM31{qm31One.ToQM31(), qm31One.ToQM31()}
		} else {
			interaction[i] = []m31.QM31{qm31One.ToQM31()}
		}
	}

	return preprocessed, trace, interaction
}

func (f *poseidonBuiltinFixture) ExpectedSum() qm31Literal {
	return f.expectedSum
}

// ╔══════════════════════════════════╗
// ║         Triple XOR 32            ║
// ╚══════════════════════════════════╝

type tripleXor32Fixture struct {
	expectedSum qm31Literal
}

func newTripleXor32Fixture(expectedSum qm31Literal) componentFixture {
	return &tripleXor32Fixture{expectedSum: expectedSum}
}

func (f *tripleXor32Fixture) Name() string {
	return "triple_xor_32"
}

func (f *tripleXor32Fixture) Build(ctx componentContext) componentUnderTest {
	verifyXor := ctx.qm31Chip.DummyInteractionElements(3)
	tripleXor := ctx.qm31Chip.DummyInteractionElements(8)

	claim := cairo_components.TripleXor32Claim{LogSize: 3}
	interactionClaim := cairo_components.TripleXor32InteractionClaim{
		ClaimedSum: qm31One.ToQM31(),
	}

	return cairo_components.NewTripleXor32(
		ctx.qm31Chip,
		verifyXor,
		tripleXor,
		claim,
		interactionClaim,
	)
}

func (f *tripleXor32Fixture) SampledValues(ctx componentContext) ([][]m31.QM31, [][]m31.QM31, [][]m31.QM31) {
	preprocessed := make([][]m31.QM31, len(cairo_components.PreprocessedColumns))

	trace := make([][]m31.QM31, 21)
	for i := range trace {
		trace[i] = []m31.QM31{qm31One.ToQM31()}
	}

	interaction := make([][]m31.QM31, 20)
	for i := 0; i < 16; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31()}
	}
	for i := 16; i < 20; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31(), qm31One.ToQM31()}
	}

	return preprocessed, trace, interaction
}

func (f *tripleXor32Fixture) ExpectedSum() qm31Literal {
	return f.expectedSum
}

// ╔══════════════════════════════════╗
// ║        Verify Instruction        ║
// ╚══════════════════════════════════╝

type verifyInstructionFixture struct {
	expectedSum qm31Literal
}

func newVerifyInstructionFixture(expectedSum qm31Literal) componentFixture {
	return &verifyInstructionFixture{expectedSum: expectedSum}
}

func (f *verifyInstructionFixture) Name() string {
	return "verify_instruction"
}

func (f *verifyInstructionFixture) Build(ctx componentContext) componentUnderTest {
	range7 := ctx.qm31Chip.DummyInteractionElements(3)
	range4 := ctx.qm31Chip.DummyInteractionElements(2)
	memoryAddress := ctx.qm31Chip.DummyInteractionElements(2)
	memoryId := ctx.qm31Chip.DummyInteractionElements(29)
	verifyInstruction := ctx.qm31Chip.DummyInteractionElements(7)

	claim := cairo_components.VerifyInstructionClaim{LogSize: 3}
	interactionClaim := cairo_components.VerifyInstructionInteractionClaim{
		ClaimedSum: qm31One.ToQM31(),
	}

	return cairo_components.NewVerifyInstruction(
		ctx.qm31Chip,
		range7,
		range4,
		memoryAddress,
		memoryId,
		verifyInstruction,
		claim,
		interactionClaim,
	)
}

func (f *verifyInstructionFixture) SampledValues(ctx componentContext) ([][]m31.QM31, [][]m31.QM31, [][]m31.QM31) {
	preprocessed := make([][]m31.QM31, len(cairo_components.PreprocessedColumns))

	trace := make([][]m31.QM31, 17)
	for i := range trace {
		trace[i] = []m31.QM31{qm31One.ToQM31()}
	}

	interaction := make([][]m31.QM31, 12)
	for i := 0; i < 8; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31()}
	}
	for i := 8; i < 12; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31(), qm31One.ToQM31()}
	}

	return preprocessed, trace, interaction
}

func (f *verifyInstructionFixture) ExpectedSum() qm31Literal {
	return f.expectedSum
}

// ╔══════════════════════════════════╗
// ║       Blake Round Sigma          ║
// ╚══════════════════════════════════╝

type blakeRoundSigmaFixture struct {
	expectedSum qm31Literal
}

func newBlakeRoundSigmaFixture(expectedSum qm31Literal) componentFixture {
	return &blakeRoundSigmaFixture{expectedSum: expectedSum}
}

func (f *blakeRoundSigmaFixture) Name() string {
	return "blake_round_sigma"
}

func (f *blakeRoundSigmaFixture) Build(ctx componentContext) componentUnderTest {
	lookup := ctx.qm31Chip.DummyInteractionElements(17)

	claim := cairo_components.BlakeRoundSigmaClaim{}
	interactionClaim := cairo_components.BlakeRoundSigmaInteractionClaim{
		ClaimedSum: qm31One.ToQM31(),
	}

	return cairo_components.NewBlakeRoundSigma(
		ctx.qm31Chip,
		lookup,
		claim,
		interactionClaim,
	)
}

func (f *blakeRoundSigmaFixture) SampledValues(ctx componentContext) ([][]m31.QM31, [][]m31.QM31, [][]m31.QM31) {
	preprocessed := make([][]m31.QM31, len(cairo_components.PreprocessedColumns))

	setPreprocessed := func(column cairo_components.PreprocessedColumn) {
		index := locatePreprocessedColumnIndex(ctx.api, column)
		preprocessed[index] = []m31.QM31{qm31One.ToQM31()}
	}

	setPreprocessed(cairo_components.NewPreprocessedColumnSeq(uints.NewU8(4)))
	for i := uint8(0); i < 16; i++ {
		setPreprocessed(cairo_components.NewPreprocessedColumnBlakeSigma(uints.NewU8(i)))
	}

	trace := make([][]m31.QM31, 1)
	trace[0] = []m31.QM31{qm31One.ToQM31()}

	interaction := make([][]m31.QM31, 4)
	for i := range interaction {
		interaction[i] = []m31.QM31{qm31One.ToQM31(), qm31One.ToQM31()}
	}

	return preprocessed, trace, interaction
}

func (f *blakeRoundSigmaFixture) ExpectedSum() qm31Literal {
	return f.expectedSum
}

// ╔══════════════════════════════════╗
// ║           Blake G                ║
// ╚══════════════════════════════════╝

type blakeGFixture struct {
	expectedSum qm31Literal
}

func newBlakeGFixture(expectedSum qm31Literal) componentFixture {
	return &blakeGFixture{expectedSum: expectedSum}
}

func (f *blakeGFixture) Name() string {
	return "blake_g"
}

func (f *blakeGFixture) Build(ctx componentContext) componentUnderTest {
	verifyXor8 := ctx.qm31Chip.DummyInteractionElements(3)
	verifyXor12 := ctx.qm31Chip.DummyInteractionElements(3)
	verifyXor4 := ctx.qm31Chip.DummyInteractionElements(3)
	verifyXor7 := ctx.qm31Chip.DummyInteractionElements(3)
	verifyXor9 := ctx.qm31Chip.DummyInteractionElements(3)
	blakeG := ctx.qm31Chip.DummyInteractionElements(20)

	claim := cairo_components.BlakeGClaim{LogSize: 3}
	interactionClaim := cairo_components.BlakeGInteractionClaim{
		ClaimedSum: qm31One.ToQM31(),
	}

	return cairo_components.NewBlakeG(
		ctx.qm31Chip,
		verifyXor8,
		verifyXor12,
		verifyXor4,
		verifyXor7,
		verifyXor9,
		blakeG,
		claim,
		interactionClaim,
	)
}

func (f *blakeGFixture) SampledValues(ctx componentContext) ([][]m31.QM31, [][]m31.QM31, [][]m31.QM31) {
	preprocessed := make([][]m31.QM31, len(cairo_components.PreprocessedColumns))

	trace := make([][]m31.QM31, 53)
	for i := range trace {
		trace[i] = []m31.QM31{qm31One.ToQM31()}
	}

	interaction := make([][]m31.QM31, 36)
	for i := 0; i < 32; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31()}
	}
	for i := 32; i < 36; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31(), qm31One.ToQM31()}
	}

	return preprocessed, trace, interaction
}

func (f *blakeGFixture) ExpectedSum() qm31Literal {
	return f.expectedSum
}

// ╔══════════════════════════════════╗
// ║          Blake Round             ║
// ╚══════════════════════════════════╝

type blakeRoundFixture struct {
	expectedSum qm31Literal
}

func newBlakeRoundFixture(expectedSum qm31Literal) componentFixture {
	return &blakeRoundFixture{expectedSum: expectedSum}
}

func (f *blakeRoundFixture) Name() string {
	return "blake_round"
}

func (f *blakeRoundFixture) Build(ctx componentContext) componentUnderTest {
	blakeRoundSigma := ctx.qm31Chip.DummyInteractionElements(17)
	rangeCheck725 := ctx.qm31Chip.DummyInteractionElements(3)
	memoryAddressToId := ctx.qm31Chip.DummyInteractionElements(2)
	memoryIdToBig := ctx.qm31Chip.DummyInteractionElements(29)
	blakeG := ctx.qm31Chip.DummyInteractionElements(20)
	blakeRound := ctx.qm31Chip.DummyInteractionElements(35)

	claim := cairo_components.BlakeRoundClaim{LogSize: 4}
	interactionClaim := cairo_components.BlakeRoundInteractionClaim{
		ClaimedSum: qm31One.ToQM31(),
	}

	return cairo_components.NewBlakeRound(
		ctx.qm31Chip,
		blakeRoundSigma,
		rangeCheck725,
		memoryAddressToId,
		memoryIdToBig,
		blakeG,
		blakeRound,
		claim,
		interactionClaim,
	)
}

func (f *blakeRoundFixture) SampledValues(ctx componentContext) ([][]m31.QM31, [][]m31.QM31, [][]m31.QM31) {
	preprocessed := make([][]m31.QM31, len(cairo_components.PreprocessedColumns))

	setPreprocessed := func(column cairo_components.PreprocessedColumn) {
		index := locatePreprocessedColumnIndex(ctx.api, column)
		preprocessed[index] = []m31.QM31{qm31One.ToQM31()}
	}

	setPreprocessed(cairo_components.NewPreprocessedColumnSeq(uints.NewU8(4)))
	for i := uint8(0); i < 16; i++ {
		setPreprocessed(cairo_components.NewPreprocessedColumnBlakeSigma(uints.NewU8(i)))
	}

	trace := make([][]m31.QM31, 212)
	for i := range trace {
		trace[i] = []m31.QM31{qm31One.ToQM31()}
	}

	interaction := make([][]m31.QM31, 120)
	for i := 0; i < 116; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31()}
	}
	for i := 116; i < 120; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31(), qm31One.ToQM31()}
	}

	return preprocessed, trace, interaction
}

func (f *blakeRoundFixture) ExpectedSum() qm31Literal {
	return f.expectedSum
}

// ╔══════════════════════════════════╗
// ║     Blake Compress Opcode        ║
// ╚══════════════════════════════════╝

type blakeCompressOpcodeFixture struct {
	expectedSum qm31Literal
}

func newBlakeCompressOpcodeFixture(expectedSum qm31Literal) componentFixture {
	return &blakeCompressOpcodeFixture{expectedSum: expectedSum}
}

func (f *blakeCompressOpcodeFixture) Name() string {
	return "blake_compress_opcode"
}

func (f *blakeCompressOpcodeFixture) Build(ctx componentContext) componentUnderTest {
	verifyInstruction := ctx.qm31Chip.DummyInteractionElements(7)
	memoryAddressToId := ctx.qm31Chip.DummyInteractionElements(2)
	memoryIdToBig := ctx.qm31Chip.DummyInteractionElements(29)
	rangeCheck725 := ctx.qm31Chip.DummyInteractionElements(3)
	verifyBitwiseXor8 := ctx.qm31Chip.DummyInteractionElements(3)
	blakeRound := ctx.qm31Chip.DummyInteractionElements(35)
	tripleXor32 := ctx.qm31Chip.DummyInteractionElements(8)
	opcodes := ctx.qm31Chip.DummyInteractionElements(3)

	claim := cairo_components.BlakeCompressOpcodeClaim{LogSize: 4}
	interactionClaim := cairo_components.BlakeCompressOpcodeInteractionClaim{
		ClaimedSum: qm31One.ToQM31(),
	}

	return cairo_components.NewBlakeCompressOpcode(
		ctx.qm31Chip,
		verifyInstruction,
		memoryAddressToId,
		memoryIdToBig,
		rangeCheck725,
		verifyBitwiseXor8,
		blakeRound,
		tripleXor32,
		opcodes,
		claim,
		interactionClaim,
	)
}

func (f *blakeCompressOpcodeFixture) SampledValues(ctx componentContext) ([][]m31.QM31, [][]m31.QM31, [][]m31.QM31) {
	preprocessed := make([][]m31.QM31, len(cairo_components.PreprocessedColumns))

	setPreprocessed := func(column cairo_components.PreprocessedColumn) {
		index := locatePreprocessedColumnIndex(ctx.api, column)
		preprocessed[index] = []m31.QM31{qm31One.ToQM31()}
	}

	setPreprocessed(cairo_components.NewPreprocessedColumnSeq(uints.NewU8(4)))

	trace := make([][]m31.QM31, 169)
	for i := range trace {
		trace[i] = []m31.QM31{qm31One.ToQM31()}
	}

	interaction := make([][]m31.QM31, 148)
	for i := 0; i < 144; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31()}
	}
	for i := 144; i < 148; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31(), qm31One.ToQM31()}
	}

	return preprocessed, trace, interaction
}

func (f *blakeCompressOpcodeFixture) ExpectedSum() qm31Literal {
	return f.expectedSum
}

// ╔══════════════════════════════════╗
// ║         Generic Opcode           ║
// ╚══════════════════════════════════╝

type genericOpcodeFixture struct {
	expectedSum qm31Literal
}

func newGenericOpcodeFixture(expectedSum qm31Literal) componentFixture {
	return &genericOpcodeFixture{expectedSum: expectedSum}
}

func (f *genericOpcodeFixture) Name() string {
	return "generic_opcode"
}

func (f *genericOpcodeFixture) Build(ctx componentContext) componentUnderTest {
	verifyInstruction := ctx.qm31Chip.DummyInteractionElements(7)
	memoryAddress := ctx.qm31Chip.DummyInteractionElements(2)
	memoryIdToBig := ctx.qm31Chip.DummyInteractionElements(29)
	rangeCheck99 := ctx.qm31Chip.DummyInteractionElements(2)
	rangeCheck19 := ctx.qm31Chip.DummyInteractionElements(1)
	opcodes := ctx.qm31Chip.DummyInteractionElements(3)

	claim := cairo_components.GenericOpcodeClaim{LogSize: 3}
	interactionClaim := cairo_components.GenericOpcodeInteractionClaim{ClaimedSum: qm31One.ToQM31()}
	return cairo_components.NewGenericOpcode(
		ctx.qm31Chip,
		verifyInstruction,
		memoryAddress,
		memoryIdToBig,
		rangeCheck99,
		rangeCheck19,
		opcodes,
		claim,
		interactionClaim,
	)
}

func (f *genericOpcodeFixture) SampledValues(ctx componentContext) ([][]m31.QM31, [][]m31.QM31, [][]m31.QM31) {
	preprocessed := make([][]m31.QM31, len(cairo_components.PreprocessedColumns))
	trace := make([][]m31.QM31, 236)
	for i := range trace {
		trace[i] = []m31.QM31{qm31One.ToQM31()}
	}

	interaction := make([][]m31.QM31, 132)
	for i := 0; i < 128; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31()}
	}
	for i := 128; i < 132; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31(), qm31One.ToQM31()}
	}

	return preprocessed, trace, interaction
}

func (f *genericOpcodeFixture) ExpectedSum() qm31Literal {
	return f.expectedSum
}

// ╔══════════════════════════════════╗
// ║  Verify Bitwise Xor 12 Fixture   ║
// ╚══════════════════════════════════╝

type verifyBitwiseXor12Fixture struct {
	expectedSum qm31Literal
}

func (f *verifyBitwiseXor12Fixture) Name() string {
	return "verify_bitwise_xor_12"
}

func (f *verifyBitwiseXor12Fixture) Build(ctx componentContext) componentUnderTest {
	elements := ctx.qm31Chip.DummyInteractionElements(3)
	return cairo_components.NewVerifyBitwiseXor12(
		ctx.qm31Chip,
		elements,
		cairo_components.VerifyBitwiseXor12InteractionClaim{ClaimedSum: qm31One.ToQM31()},
	)
}

func (f *verifyBitwiseXor12Fixture) SampledValues(ctx componentContext) ([][]m31.QM31, [][]m31.QM31, [][]m31.QM31) {
	preprocessed := make([][]m31.QM31, len(cairo_components.PreprocessedColumns))
	for i := uint8(0); i < 3; i++ {
		column := cairo_components.NewPreprocessedColumnBitwiseXor(uints.NewU8(10), uints.NewU8(i))
		index := locatePreprocessedColumnIndex(ctx.api, column)
		preprocessed[index] = []m31.QM31{qm31One.ToQM31()}
	}

	trace := make([][]m31.QM31, 16)
	for i := range trace {
		trace[i] = []m31.QM31{qm31One.ToQM31()}
	}

	interaction := make([][]m31.QM31, 32)
	for i := 0; i < 28; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31()}
	}
	for i := 28; i < 32; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31(), qm31One.ToQM31()}
	}

	return preprocessed, trace, interaction
}

func (f *verifyBitwiseXor12Fixture) RandomCoeff() qm31Literal {
	return qm31One
}

func (f *verifyBitwiseXor12Fixture) ExpectedSum() qm31Literal {
	return f.expectedSum
}

// ╔══════════════════════════════════╗
// ║            Add Opcode            ║
// ╚══════════════════════════════════╝

type addOpcodeFixture struct {
	expectedSum qm31Literal
}

func newAddOpcodeFixture(expectedSum qm31Literal) componentFixture {
	return &addOpcodeFixture{expectedSum: expectedSum}
}

func (f *addOpcodeFixture) Name() string {
	return "add_opcode"
}

func (f *addOpcodeFixture) Build(ctx componentContext) componentUnderTest {
	verifyInstruction := ctx.qm31Chip.DummyInteractionElements(7)
	memoryAddress := ctx.qm31Chip.DummyInteractionElements(2)
	memoryIdToBig := ctx.qm31Chip.DummyInteractionElements(29)
	opcodes := ctx.qm31Chip.DummyInteractionElements(3)

	claim := cairo_components.AddOpcodeClaim{LogSize: 3}
	interactionClaim := cairo_components.AddOpcodeInteractionClaim{ClaimedSum: qm31One.ToQM31()}

	return cairo_components.NewAddOpcode(
		ctx.qm31Chip,
		verifyInstruction,
		memoryAddress,
		memoryIdToBig,
		opcodes,
		claim,
		interactionClaim,
	)
}

func (f *addOpcodeFixture) SampledValues(ctx componentContext) ([][]m31.QM31, [][]m31.QM31, [][]m31.QM31) {
	preprocessed := make([][]m31.QM31, len(cairo_components.PreprocessedColumns))

	trace := make([][]m31.QM31, 103)
	for i := range trace {
		trace[i] = []m31.QM31{qm31One.ToQM31()}
	}

	interaction := make([][]m31.QM31, 20)
	for i := 0; i < 16; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31()}
	}
	for i := 16; i < 20; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31(), qm31One.ToQM31()}
	}

	return preprocessed, trace, interaction
}

func (f *addOpcodeFixture) ExpectedSum() qm31Literal {
	return f.expectedSum
}

// ╔══════════════════════════════════╗
// ║       Memory Address To ID       ║
// ╚══════════════════════════════════╝

type memoryAddressToIdFixture struct {
	expectedSum qm31Literal
}

func newMemoryAddressToIdFixture(expectedSum qm31Literal) componentFixture {
	return &memoryAddressToIdFixture{expectedSum: expectedSum}
}

func (f *memoryAddressToIdFixture) Name() string {
	return "memory_address_to_id"
}

func (f *memoryAddressToIdFixture) Build(ctx componentContext) componentUnderTest {
	interactionElements := ctx.qm31Chip.DummyInteractionElements(2)
	claim := cairo_components.MemoryAddressToIdClaim{
		LogSize: uints.NewU8(4),
	}
	interactionClaim := cairo_components.MemoryAddressToIdInteractionClaim{
		ClaimedSum: qm31One.ToQM31(),
	}

	return cairo_components.NewMemoryAddressToId(
		ctx.api,
		ctx.qm31Chip,
		interactionElements,
		claim,
		interactionClaim,
		qm31One.ToQM31(),
	)
}

func (f *memoryAddressToIdFixture) SampledValues(ctx componentContext) ([][]m31.QM31, [][]m31.QM31, [][]m31.QM31) {
	preprocessed := make([][]m31.QM31, len(cairo_components.PreprocessedColumns))
	seqColumn := cairo_components.NewPreprocessedColumnSeq(uints.NewU8(4))
	index := locatePreprocessedColumnIndex(ctx.api, seqColumn)
	preprocessed[index] = []m31.QM31{qm31One.ToQM31()}

	trace := make([][]m31.QM31, 16)
	for i := 0; i < len(trace); i++ {
		trace[i] = []m31.QM31{qm31One.ToQM31()}
	}

	interaction := make([][]m31.QM31, 16)
	for i := 0; i < 12; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31()}
	}
	for i := 12; i < len(interaction); i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31(), qm31One.ToQM31()}
	}

	return preprocessed, trace, interaction
}

func (f *memoryAddressToIdFixture) ExpectedSum() qm31Literal {
	return f.expectedSum
}

// ╔══════════════════════════════════╗
// ║      Generic Lookup Fixtures     ║
// ╚══════════════════════════════════╝

type lookupFixture struct {
	name           string
	logSize        uint8
	interactionKey string
	expectedSum    qm31Literal
	builder        func(componentContext, m31.InteractionElements) componentUnderTest
	factories      []func() cairo_components.PreprocessedColumn
}

func newRangeCheck11Fixture(expected qm31Literal) componentFixture {
	return &lookupFixture{
		name:           "range_check_11",
		logSize:        11,
		interactionKey: "",
		expectedSum:    expected,
		factories: []func() cairo_components.PreprocessedColumn{
			func() cairo_components.PreprocessedColumn {
				return cairo_components.NewPreprocessedColumnSeq(uints.NewU8(11))
			},
		},
		builder: func(ctx componentContext, elements m31.InteractionElements) componentUnderTest {
			return cairo_components.NewRangeCheck11(
				ctx.qm31Chip,
				elements,
				cairo_components.RangeCheck11InteractionClaim{ClaimedSum: qm31One.ToQM31()},
			)
		},
	}
}

func newRangeCheck12Fixture(expected qm31Literal) componentFixture {
	return &lookupFixture{
		name:           "range_check_12",
		logSize:        12,
		interactionKey: "",
		expectedSum:    expected,
		factories: []func() cairo_components.PreprocessedColumn{
			func() cairo_components.PreprocessedColumn {
				return cairo_components.NewPreprocessedColumnSeq(uints.NewU8(12))
			},
		},
		builder: func(ctx componentContext, elements m31.InteractionElements) componentUnderTest {
			return cairo_components.NewRangeCheck12(
				ctx.qm31Chip,
				elements,
				cairo_components.RangeCheck12InteractionClaim{ClaimedSum: qm31One.ToQM31()},
			)
		},
	}
}

func newRangeCheck18Fixture(expected qm31Literal) componentFixture {
	return &lookupFixture{
		name:           "range_check_18",
		logSize:        18,
		interactionKey: "rc_18",
		expectedSum:    expected,
		factories: []func() cairo_components.PreprocessedColumn{
			func() cairo_components.PreprocessedColumn {
				return cairo_components.NewPreprocessedColumnSeq(uints.NewU8(18))
			},
		},
		builder: func(ctx componentContext, elements m31.InteractionElements) componentUnderTest {
			return cairo_components.NewRangeCheck18(
				ctx.qm31Chip,
				elements,
				cairo_components.RangeCheck18InteractionClaim{ClaimedSum: qm31One.ToQM31()},
			)
		},
	}
}

func newRangeCheck19Fixture(expected qm31Literal) componentFixture {
	return &lookupFixture{
		name:           "range_check_19",
		logSize:        19,
		interactionKey: "rc_19",
		expectedSum:    expected,
		factories: []func() cairo_components.PreprocessedColumn{
			func() cairo_components.PreprocessedColumn {
				return cairo_components.NewPreprocessedColumnSeq(uints.NewU8(19))
			},
		},
		builder: func(ctx componentContext, elements m31.InteractionElements) componentUnderTest {
			return cairo_components.NewRangeCheck19(
				ctx.qm31Chip,
				elements,
				cairo_components.RangeCheck19InteractionClaim{ClaimedSum: qm31One.ToQM31()},
			)
		},
	}
}

func newRangeCheck3_6_6_3Fixture(expected qm31Literal) componentFixture {
	values := []uints.U8{
		uints.NewU8(3),
		uints.NewU8(6),
		uints.NewU8(6),
		uints.NewU8(3),
	}
	return &lookupFixture{
		name:           "range_check_3_6_6_3",
		logSize:        18,
		interactionKey: "rc_3_6_6_3",
		expectedSum:    expected,
		factories: []func() cairo_components.PreprocessedColumn{
			func() cairo_components.PreprocessedColumn {
				return cairo_components.NewPreprocessedColumnRangeCheck4(values, uints.NewU8(0))
			},
			func() cairo_components.PreprocessedColumn {
				return cairo_components.NewPreprocessedColumnRangeCheck4(values, uints.NewU8(1))
			},
			func() cairo_components.PreprocessedColumn {
				return cairo_components.NewPreprocessedColumnRangeCheck4(values, uints.NewU8(2))
			},
			func() cairo_components.PreprocessedColumn {
				return cairo_components.NewPreprocessedColumnRangeCheck4(values, uints.NewU8(3))
			},
		},
		builder: func(ctx componentContext, elements m31.InteractionElements) componentUnderTest {
			return cairo_components.NewRangeCheck3_6_6_3(
				ctx.qm31Chip,
				elements,
				cairo_components.RangeCheck3_6_6_3InteractionClaim{ClaimedSum: qm31One.ToQM31()},
			)
		},
	}
}

func newRangeCheck3_3_3_3_3Fixture(expected qm31Literal) componentFixture {
	values := []uints.U8{
		uints.NewU8(3),
		uints.NewU8(3),
		uints.NewU8(3),
		uints.NewU8(3),
		uints.NewU8(3),
	}
	return &lookupFixture{
		name:           "range_check_3_3_3_3_3",
		logSize:        15,
		interactionKey: "rc_3_3_3_3_3",
		expectedSum:    expected,
		factories: []func() cairo_components.PreprocessedColumn{
			func() cairo_components.PreprocessedColumn {
				return cairo_components.NewPreprocessedColumnRangeCheck5(values, uints.NewU8(0))
			},
			func() cairo_components.PreprocessedColumn {
				return cairo_components.NewPreprocessedColumnRangeCheck5(values, uints.NewU8(1))
			},
			func() cairo_components.PreprocessedColumn {
				return cairo_components.NewPreprocessedColumnRangeCheck5(values, uints.NewU8(2))
			},
			func() cairo_components.PreprocessedColumn {
				return cairo_components.NewPreprocessedColumnRangeCheck5(values, uints.NewU8(3))
			},
			func() cairo_components.PreprocessedColumn {
				return cairo_components.NewPreprocessedColumnRangeCheck5(values, uints.NewU8(4))
			},
		},
		builder: func(ctx componentContext, elements m31.InteractionElements) componentUnderTest {
			return cairo_components.NewRangeCheck3_3_3_3_3(
				ctx.qm31Chip,
				elements,
				cairo_components.RangeCheck3_3_3_3_3InteractionClaim{ClaimedSum: qm31One.ToQM31()},
			)
		},
	}
}

func newRangeCheck4_3Fixture(expected qm31Literal) componentFixture {
	values := []uints.U8{
		uints.NewU8(4),
		uints.NewU8(3),
	}
	return &lookupFixture{
		name:           "range_check_4_3",
		logSize:        7,
		interactionKey: "rc_4_3",
		expectedSum:    expected,
		factories: []func() cairo_components.PreprocessedColumn{
			func() cairo_components.PreprocessedColumn {
				return cairo_components.NewPreprocessedColumnRangeCheck2(values, uints.NewU8(0))
			},
			func() cairo_components.PreprocessedColumn {
				return cairo_components.NewPreprocessedColumnRangeCheck2(values, uints.NewU8(1))
			},
		},
		builder: func(ctx componentContext, elements m31.InteractionElements) componentUnderTest {
			return cairo_components.NewRangeCheck4_3(
				ctx.qm31Chip,
				elements,
				cairo_components.RangeCheck4_3InteractionClaim{ClaimedSum: qm31One.ToQM31()},
			)
		},
	}
}

func newRangeCheck4_4Fixture(expected qm31Literal) componentFixture {
	values := []uints.U8{
		uints.NewU8(4),
		uints.NewU8(4),
	}
	return &lookupFixture{
		name:           "range_check_4_4",
		logSize:        8,
		interactionKey: "rc_4_4",
		expectedSum:    expected,
		factories: []func() cairo_components.PreprocessedColumn{
			func() cairo_components.PreprocessedColumn {
				return cairo_components.NewPreprocessedColumnRangeCheck2(values, uints.NewU8(0))
			},
			func() cairo_components.PreprocessedColumn {
				return cairo_components.NewPreprocessedColumnRangeCheck2(values, uints.NewU8(1))
			},
		},
		builder: func(ctx componentContext, elements m31.InteractionElements) componentUnderTest {
			return cairo_components.NewRangeCheck4_4(
				ctx.qm31Chip,
				elements,
				cairo_components.RangeCheck4_4InteractionClaim{ClaimedSum: qm31One.ToQM31()},
			)
		},
	}
}

func newRangeCheck4_4_4_4Fixture(expected qm31Literal) componentFixture {
	values := []uints.U8{
		uints.NewU8(4),
		uints.NewU8(4),
		uints.NewU8(4),
		uints.NewU8(4),
	}
	return &lookupFixture{
		name:           "range_check_4_4_4_4",
		logSize:        16,
		interactionKey: "rc_4_4_4_4",
		expectedSum:    expected,
		factories: []func() cairo_components.PreprocessedColumn{
			func() cairo_components.PreprocessedColumn {
				return cairo_components.NewPreprocessedColumnRangeCheck4(values, uints.NewU8(0))
			},
			func() cairo_components.PreprocessedColumn {
				return cairo_components.NewPreprocessedColumnRangeCheck4(values, uints.NewU8(1))
			},
			func() cairo_components.PreprocessedColumn {
				return cairo_components.NewPreprocessedColumnRangeCheck4(values, uints.NewU8(2))
			},
			func() cairo_components.PreprocessedColumn {
				return cairo_components.NewPreprocessedColumnRangeCheck4(values, uints.NewU8(3))
			},
		},
		builder: func(ctx componentContext, elements m31.InteractionElements) componentUnderTest {
			return cairo_components.NewRangeCheck4_4_4_4(
				ctx.qm31Chip,
				elements,
				cairo_components.RangeCheck4_4_4_4InteractionClaim{ClaimedSum: qm31One.ToQM31()},
			)
		},
	}
}

func newRangeCheck5_4Fixture(expected qm31Literal) componentFixture {
	values := []uints.U8{
		uints.NewU8(5),
		uints.NewU8(4),
	}
	return &lookupFixture{
		name:           "range_check_5_4",
		logSize:        9,
		interactionKey: "rc_5_4",
		expectedSum:    expected,
		factories: []func() cairo_components.PreprocessedColumn{
			func() cairo_components.PreprocessedColumn {
				return cairo_components.NewPreprocessedColumnRangeCheck2(values, uints.NewU8(0))
			},
			func() cairo_components.PreprocessedColumn {
				return cairo_components.NewPreprocessedColumnRangeCheck2(values, uints.NewU8(1))
			},
		},
		builder: func(ctx componentContext, elements m31.InteractionElements) componentUnderTest {
			return cairo_components.NewRangeCheck5_4(
				ctx.qm31Chip,
				elements,
				cairo_components.RangeCheck5_4InteractionClaim{ClaimedSum: qm31One.ToQM31()},
			)
		},
	}
}

func newRangeCheck6Fixture(expected qm31Literal) componentFixture {
	return &lookupFixture{
		name:           "range_check_6",
		logSize:        6,
		interactionKey: "rc_6",
		expectedSum:    expected,
		factories: []func() cairo_components.PreprocessedColumn{
			func() cairo_components.PreprocessedColumn {
				return cairo_components.NewPreprocessedColumnSeq(uints.NewU8(6))
			},
		},
		builder: func(ctx componentContext, elements m31.InteractionElements) componentUnderTest {
			return cairo_components.NewRangeCheck6(
				ctx.qm31Chip,
				elements,
				cairo_components.RangeCheck6InteractionClaim{ClaimedSum: qm31One.ToQM31()},
			)
		},
	}
}

func newRangeCheck7_2_5Fixture(expected qm31Literal) componentFixture {
	values := []uints.U8{
		uints.NewU8(7),
		uints.NewU8(2),
		uints.NewU8(5),
	}
	return &lookupFixture{
		name:           "range_check_7_2_5",
		logSize:        14,
		interactionKey: "rc_7_2_5",
		expectedSum:    expected,
		factories: []func() cairo_components.PreprocessedColumn{
			func() cairo_components.PreprocessedColumn {
				return cairo_components.NewPreprocessedColumnRangeCheck3(values, uints.NewU8(0))
			},
			func() cairo_components.PreprocessedColumn {
				return cairo_components.NewPreprocessedColumnRangeCheck3(values, uints.NewU8(1))
			},
			func() cairo_components.PreprocessedColumn {
				return cairo_components.NewPreprocessedColumnRangeCheck3(values, uints.NewU8(2))
			},
		},
		builder: func(ctx componentContext, elements m31.InteractionElements) componentUnderTest {
			return cairo_components.NewRangeCheck7_2_5(
				ctx.qm31Chip,
				elements,
				cairo_components.RangeCheck7_2_5InteractionClaim{ClaimedSum: qm31One.ToQM31()},
			)
		},
	}
}

func newRangeCheck8Fixture(expected qm31Literal) componentFixture {
	return &lookupFixture{
		name:           "range_check_8",
		logSize:        8,
		interactionKey: "rc_8",
		expectedSum:    expected,
		factories: []func() cairo_components.PreprocessedColumn{
			func() cairo_components.PreprocessedColumn {
				return cairo_components.NewPreprocessedColumnSeq(uints.NewU8(8))
			},
		},
		builder: func(ctx componentContext, elements m31.InteractionElements) componentUnderTest {
			return cairo_components.NewRangeCheck8(
				ctx.qm31Chip,
				elements,
				cairo_components.RangeCheck8InteractionClaim{ClaimedSum: qm31One.ToQM31()},
			)
		},
	}
}

func newRangeCheck9_9Fixture(expected qm31Literal) componentFixture {
	values := []uints.U8{
		uints.NewU8(9),
		uints.NewU8(9),
	}
	return &lookupFixture{
		name:           "range_check_9_9",
		logSize:        18,
		interactionKey: "rc_9_9",
		expectedSum:    expected,
		factories: []func() cairo_components.PreprocessedColumn{
			func() cairo_components.PreprocessedColumn {
				return cairo_components.NewPreprocessedColumnRangeCheck2(values, uints.NewU8(0))
			},
			func() cairo_components.PreprocessedColumn {
				return cairo_components.NewPreprocessedColumnRangeCheck2(values, uints.NewU8(1))
			},
		},
		builder: func(ctx componentContext, elements m31.InteractionElements) componentUnderTest {
			return cairo_components.NewRangeCheck9_9(
				ctx.qm31Chip,
				elements,
				cairo_components.RangeCheck9_9InteractionClaim{ClaimedSum: qm31One.ToQM31()},
			)
		},
	}
}

func newRangeCheckBuiltin96Fixture(expected qm31Literal) componentFixture {
	return &rangeCheckBuiltin96Fixture{expectedSum: expected}
}

type rangeCheckBuiltin96Fixture struct {
	expectedSum qm31Literal
}

func (f *rangeCheckBuiltin96Fixture) Name() string {
	return "range_check_builtin_bits_96"
}

func (f *rangeCheckBuiltin96Fixture) Build(ctx componentContext) componentUnderTest {
	memoryAddress := ctx.qm31Chip.DummyInteractionElements(2)
	rangeCheck6 := ctx.qm31Chip.DummyInteractionElements(1)
	memoryIdToBig := ctx.qm31Chip.DummyInteractionElements(29)

	claim := cairo_components.RangeCheck96BuiltinClaim{
		LogSize:                4,
		RangeCheckSegmentStart: 3,
	}
	interactionClaim := cairo_components.RangeCheck96BuiltinInteractionClaim{
		ClaimedSum: qm31One.ToQM31(),
	}

	return cairo_components.NewRangeCheck96Builtin(
		ctx.qm31Chip,
		memoryAddress,
		rangeCheck6,
		memoryIdToBig,
		claim,
		interactionClaim,
	)
}

func (f *rangeCheckBuiltin96Fixture) SampledValues(ctx componentContext) ([][]m31.QM31, [][]m31.QM31, [][]m31.QM31) {
	preprocessed := make([][]m31.QM31, len(cairo_components.PreprocessedColumns))
	seqColumn := cairo_components.NewPreprocessedColumnSeq(uints.NewU8(4))
	index := locatePreprocessedColumnIndex(ctx.api, seqColumn)
	preprocessed[index] = []m31.QM31{qm31One.ToQM31()}

	trace := make([][]m31.QM31, 12)
	for i := range trace {
		trace[i] = []m31.QM31{qm31One.ToQM31()}
	}

	interaction := make([][]m31.QM31, 8)
	for i := 0; i < 4; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31()}
	}
	for i := 4; i < 8; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31(), qm31One.ToQM31()}
	}

	return preprocessed, trace, interaction
}

func (f *rangeCheckBuiltin96Fixture) ExpectedSum() qm31Literal {
	return f.expectedSum
}

func newRangeCheckBuiltin128Fixture(expected qm31Literal) componentFixture {
	return &rangeCheckBuiltin128Fixture{expectedSum: expected}
}

type rangeCheckBuiltin128Fixture struct {
	expectedSum qm31Literal
}

func (f *rangeCheckBuiltin128Fixture) Name() string {
	return "range_check_builtin_bits_128"
}

func (f *rangeCheckBuiltin128Fixture) Build(ctx componentContext) componentUnderTest {
	memoryAddress := ctx.qm31Chip.DummyInteractionElements(2)
	memoryIdToBig := ctx.qm31Chip.DummyInteractionElements(29)

	claim := cairo_components.RangeCheck128BuiltinClaim{
		LogSize:                4,
		RangeCheckSegmentStart: 3,
	}
	interactionClaim := cairo_components.RangeCheck128BuiltinInteractionClaim{
		ClaimedSum: qm31One.ToQM31(),
	}

	return cairo_components.NewRangeCheck128Builtin(
		ctx.qm31Chip,
		memoryAddress,
		memoryIdToBig,
		claim,
		interactionClaim,
	)
}

func (f *rangeCheckBuiltin128Fixture) SampledValues(ctx componentContext) ([][]m31.QM31, [][]m31.QM31, [][]m31.QM31) {
	preprocessed := make([][]m31.QM31, len(cairo_components.PreprocessedColumns))
	seqColumn := cairo_components.NewPreprocessedColumnSeq(uints.NewU8(4))
	index := locatePreprocessedColumnIndex(ctx.api, seqColumn)
	preprocessed[index] = []m31.QM31{qm31One.ToQM31()}

	trace := make([][]m31.QM31, 17)
	for i := range trace {
		trace[i] = []m31.QM31{qm31One.ToQM31()}
	}

	interaction := make([][]m31.QM31, 4)
	for i := 0; i < 4; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31(), qm31One.ToQM31()}
	}

	return preprocessed, trace, interaction
}

func (f *rangeCheckBuiltin128Fixture) ExpectedSum() qm31Literal {
	return f.expectedSum
}

func newRangeCheckFelt252Width27Fixture(expected qm31Literal) componentFixture {
	return &rangeCheckFelt252Width27Fixture{expectedSum: expected}
}

type rangeCheckFelt252Width27Fixture struct {
	expectedSum qm31Literal
}

func (f *rangeCheckFelt252Width27Fixture) Name() string {
	return "range_check_felt_252_width_27"
}

func (f *rangeCheckFelt252Width27Fixture) Build(ctx componentContext) componentUnderTest {
	rangeCheck9_9 := ctx.qm31Chip.DummyInteractionElements(2)
	rangeCheck18 := ctx.qm31Chip.DummyInteractionElements(1)
	rangeCheckFelt := ctx.qm31Chip.DummyInteractionElements(10)

	claim := cairo_components.RangeCheckFelt252Width27Claim{
		LogSize: 3,
	}
	interactionClaim := cairo_components.RangeCheckFelt252Width27InteractionClaim{
		ClaimedSum: qm31One.ToQM31(),
	}

	return cairo_components.NewRangeCheckFelt252Width27(
		ctx.qm31Chip,
		rangeCheck9_9,
		rangeCheck18,
		rangeCheckFelt,
		claim,
		interactionClaim,
	)
}

func (f *rangeCheckFelt252Width27Fixture) SampledValues(ctx componentContext) ([][]m31.QM31, [][]m31.QM31, [][]m31.QM31) {
	preprocessed := make([][]m31.QM31, len(cairo_components.PreprocessedColumns))

	trace := make([][]m31.QM31, 20)
	for i := range trace {
		trace[i] = []m31.QM31{qm31One.ToQM31()}
	}

	interaction := make([][]m31.QM31, 32)
	for i := 0; i < 28; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31()}
	}
	for i := 28; i < 32; i++ {
		interaction[i] = []m31.QM31{qm31One.ToQM31(), qm31One.ToQM31()}
	}

	return preprocessed, trace, interaction
}

func (f *rangeCheckFelt252Width27Fixture) ExpectedSum() qm31Literal {
	return f.expectedSum
}

func newVerifyBitwiseXor4Fixture(expected qm31Literal) componentFixture {
	return &lookupFixture{
		name:           "verify_bitwise_xor_4",
		logSize:        8,
		interactionKey: "verify_bitwise_xor_4",
		expectedSum:    expected,
		factories: []func() cairo_components.PreprocessedColumn{
			func() cairo_components.PreprocessedColumn {
				return cairo_components.NewPreprocessedColumnBitwiseXor(uints.NewU8(4), uints.NewU8(0))
			},
			func() cairo_components.PreprocessedColumn {
				return cairo_components.NewPreprocessedColumnBitwiseXor(uints.NewU8(4), uints.NewU8(1))
			},
			func() cairo_components.PreprocessedColumn {
				return cairo_components.NewPreprocessedColumnBitwiseXor(uints.NewU8(4), uints.NewU8(2))
			},
		},
		builder: func(ctx componentContext, elements m31.InteractionElements) componentUnderTest {
			return cairo_components.NewVerifyBitwiseXor4(
				ctx.qm31Chip,
				elements,
				cairo_components.VerifyBitwiseXor4InteractionClaim{ClaimedSum: qm31One.ToQM31()},
			)
		},
	}
}

func newVerifyBitwiseXor7Fixture(expected qm31Literal) componentFixture {
	return &lookupFixture{
		name:           "verify_bitwise_xor_7",
		logSize:        14,
		interactionKey: "verify_bitwise_xor_7",
		expectedSum:    expected,
		factories: []func() cairo_components.PreprocessedColumn{
			func() cairo_components.PreprocessedColumn {
				return cairo_components.NewPreprocessedColumnBitwiseXor(uints.NewU8(7), uints.NewU8(0))
			},
			func() cairo_components.PreprocessedColumn {
				return cairo_components.NewPreprocessedColumnBitwiseXor(uints.NewU8(7), uints.NewU8(1))
			},
			func() cairo_components.PreprocessedColumn {
				return cairo_components.NewPreprocessedColumnBitwiseXor(uints.NewU8(7), uints.NewU8(2))
			},
		},
		builder: func(ctx componentContext, elements m31.InteractionElements) componentUnderTest {
			return cairo_components.NewVerifyBitwiseXor7(
				ctx.qm31Chip,
				elements,
				cairo_components.VerifyBitwiseXor7InteractionClaim{ClaimedSum: qm31One.ToQM31()},
			)
		},
	}
}

func newVerifyBitwiseXor8Fixture(expected qm31Literal) componentFixture {
	return &lookupFixture{
		name:           "verify_bitwise_xor_8",
		logSize:        16,
		interactionKey: "verify_bitwise_xor_8",
		expectedSum:    expected,
		factories: []func() cairo_components.PreprocessedColumn{
			func() cairo_components.PreprocessedColumn {
				return cairo_components.NewPreprocessedColumnBitwiseXor(uints.NewU8(8), uints.NewU8(0))
			},
			func() cairo_components.PreprocessedColumn {
				return cairo_components.NewPreprocessedColumnBitwiseXor(uints.NewU8(8), uints.NewU8(1))
			},
			func() cairo_components.PreprocessedColumn {
				return cairo_components.NewPreprocessedColumnBitwiseXor(uints.NewU8(8), uints.NewU8(2))
			},
		},
		builder: func(ctx componentContext, elements m31.InteractionElements) componentUnderTest {
			return cairo_components.NewVerifyBitwiseXor8(
				ctx.qm31Chip,
				elements,
				cairo_components.VerifyBitwiseXor8InteractionClaim{ClaimedSum: qm31One.ToQM31()},
			)
		},
	}
}

func newVerifyBitwiseXor9Fixture(expected qm31Literal) componentFixture {
	return &lookupFixture{
		name:           "verify_bitwise_xor_9",
		logSize:        18,
		interactionKey: "verify_bitwise_xor_9",
		expectedSum:    expected,
		factories: []func() cairo_components.PreprocessedColumn{
			func() cairo_components.PreprocessedColumn {
				return cairo_components.NewPreprocessedColumnBitwiseXor(uints.NewU8(9), uints.NewU8(0))
			},
			func() cairo_components.PreprocessedColumn {
				return cairo_components.NewPreprocessedColumnBitwiseXor(uints.NewU8(9), uints.NewU8(1))
			},
			func() cairo_components.PreprocessedColumn {
				return cairo_components.NewPreprocessedColumnBitwiseXor(uints.NewU8(9), uints.NewU8(2))
			},
		},
		builder: func(ctx componentContext, elements m31.InteractionElements) componentUnderTest {
			return cairo_components.NewVerifyBitwiseXor9(
				ctx.qm31Chip,
				elements,
				cairo_components.VerifyBitwiseXor9InteractionClaim{ClaimedSum: qm31One.ToQM31()},
			)
		},
	}
}

func newVerifyBitwiseXor12Fixture(expected qm31Literal) componentFixture {
	return &verifyBitwiseXor12Fixture{expectedSum: expected}
}

func (f *lookupFixture) Name() string {
	return f.name
}

func (f *lookupFixture) Build(ctx componentContext) componentUnderTest {
	elements := ctx.qm31Chip.DummyInteractionElements(len(f.factories))
	return f.builder(ctx, elements)
}

func (f *lookupFixture) SampledValues(ctx componentContext) ([][]m31.QM31, [][]m31.QM31, [][]m31.QM31) {
	preprocessed := make([][]m31.QM31, len(cairo_components.PreprocessedColumns))
	if len(f.factories) == 0 {
		f.factories = []func() cairo_components.PreprocessedColumn{
			func() cairo_components.PreprocessedColumn {
				return cairo_components.NewPreprocessedColumnSeq(uints.NewU8(f.logSize))
			},
		}
	}
	for _, factory := range f.factories {
		column := factory()
		index := locatePreprocessedColumnIndex(ctx.api, column)
		preprocessed[index] = []m31.QM31{qm31One.ToQM31()}
	}

	trace := make([][]m31.QM31, 1)
	trace[0] = []m31.QM31{qm31One.ToQM31()}

	interaction := make([][]m31.QM31, 4)
	for i := range interaction {
		interaction[i] = []m31.QM31{qm31One.ToQM31(), qm31One.ToQM31()}
	}

	return preprocessed, trace, interaction
}

func (f *lookupFixture) ExpectedSum() qm31Literal {
	return f.expectedSum
}

// ╔══════════════════════════════════╗
// ║        Literal Helpers           ║
// ╚══════════════════════════════════╝

type qm31Literal struct {
	AReal uint64 `json:"aReal"`
	AImag uint64 `json:"aImag"`
	BReal uint64 `json:"bReal"`
	BImag uint64 `json:"bImag"`
}

func (q qm31Literal) ToQM31() m31.QM31 {
	return m31.NewQM31Unchecked(q.AReal, q.AImag, q.BReal, q.BImag)
}

var qm31One = qm31Literal{AReal: 1}

func locatePreprocessedColumnIndex(api frontend.API, target cairo_components.PreprocessedColumn) int {
	targetKey := target.Key(api)
	for idx, candidate := range cairo_components.PreprocessedColumns {
		if candidate.Key(api) == targetKey {
			return idx
		}
	}
	panic("requested preprocessed column not found")
}
