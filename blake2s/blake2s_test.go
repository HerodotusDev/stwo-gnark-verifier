package blake2s_test

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/HerodotusDev/stwo-gnark-verifier/blake2s"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
	"github.com/consensys/gnark/test/unsafekzg"
)

// Test vectors for Blake2s compression function
// Expected H from Appendix B in https://datatracker.ietf.org/doc/html/rfc7693
// T and F set from C reference implementation
var (
	testStateH = [8]uints.U32{
		uints.NewU32(0x6B08E647),
		uints.NewU32(0xBB67AE85),
		uints.NewU32(0x3C6EF372),
		uints.NewU32(0xA54FF53A),
		uints.NewU32(0x510E527F),
		uints.NewU32(0x9B05688C),
		uints.NewU32(0x1F83D9AB),
		uints.NewU32(0x5BE0CD19),
	}
	testStateT = [2]uints.U32{
		uints.NewU32(3), // hashing "abc": 3 bytes
		uints.NewU32(0),
	}
	testStateF = [2]uints.U32{
		uints.NewU32(4294967295), // final compression
		uints.NewU32(0),
	}
	testIn = [16]uints.U32{
		uints.NewU32(0x00636261), // "abc"
		uints.NewU32(0x00000000),
		uints.NewU32(0x00000000),
		uints.NewU32(0x00000000),
		uints.NewU32(0x00000000),
		uints.NewU32(0x00000000),
		uints.NewU32(0x00000000),
		uints.NewU32(0x00000000),
		uints.NewU32(0x00000000),
		uints.NewU32(0x00000000),
		uints.NewU32(0x00000000),
		uints.NewU32(0x00000000),
		uints.NewU32(0x00000000),
		uints.NewU32(0x00000000),
		uints.NewU32(0x00000000),
		uints.NewU32(0x00000000),
	}
	testExpectedH = [8]uints.U32{
		uints.NewU32(0x8C5E8C50),
		uints.NewU32(0xE2147C32),
		uints.NewU32(0xA32BA7E1),
		uints.NewU32(0x2F45EB4E),
		uints.NewU32(0x208B4537),
		uints.NewU32(0x293AD69E),
		uints.NewU32(0x4C9B994D),
		uints.NewU32(0x82596786),
	}
)

// ╔══════════════════════════════════╗
// ║       Blake2s Compress Test      ║
// ╚══════════════════════════════════╝

type TestBlake2sCompressCircuit struct {
	StateH    [8]uints.U32
	StateT    [2]uints.U32
	StateF    [2]uints.U32
	In        [16]uints.U32
	ExpectedH [8]uints.U32
}

func (c *TestBlake2sCompressCircuit) Define(api frontend.API) error {
	state := blake2s.Blake2sState{
		H: c.StateH,
		T: c.StateT,
		F: c.StateF,
	}

	uapi, err := uints.NewBinaryField[uints.U32](api)
	if err != nil {
		return err
	}

	blake2sChip := blake2s.NewBlake2sChip(api)
	state = blake2sChip.Compress(uapi, state, c.In)

	for i := range state.H {
		uapi.AssertEq(state.H[i], c.ExpectedH[i])
	}
	return nil
}

func TestBlake2sCompression(t *testing.T) {
	witness := TestBlake2sCompressCircuit{
		StateH:    testStateH,
		StateT:    testStateT,
		StateF:    testStateF,
		In:        testIn,
		ExpectedH: testExpectedH,
	}
	assert := test.NewAssert(t)
	assert.ProverSucceeded(&TestBlake2sCompressCircuit{}, &witness,
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16),
		test.NoProverChecks(),
		test.NoFuzzing())
}

// ╔══════════════════════════════════╗
// ║       Blake2s Hash Test          ║
// ╚══════════════════════════════════╝

type blake2sHashCircuit struct {
	In        [3]uints.U8
	ExpectedH [8]uints.U32
}

func (c *blake2sHashCircuit) Define(api frontend.API) error {
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		return err
	}

	blake2sChip := blake2s.NewBlake2sChip(api)
	state := blake2sChip.Blake2s(uapi, c.In[:])

	for i := range state.H {
		uapi.AssertEq(state.H[i], c.ExpectedH[i])
	}
	return nil
}

func TestBlake2sHashABC(t *testing.T) {
	witness := blake2sHashCircuit{
		In: [3]uints.U8{
			uints.NewU8(0x61), // 'a'
			uints.NewU8(0x62), // 'b'
			uints.NewU8(0x63), // 'c'
		},
		ExpectedH: testExpectedH,
	}
	assert := test.NewAssert(t)
	assert.ProverSucceeded(&blake2sHashCircuit{}, &witness,
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16),
		test.NoProverChecks(),
		test.NoFuzzing())
}

// ╔══════════════════════════════════╗
// ║       Blake2s Hash Bench         ║
// ╚══════════════════════════════════╝

type durations struct {
	compile int64
	setup   int64
	prove   int64
	verify  int64
}
type blake2sHashBenchCircuit struct {
	In [128]uints.U8
}

func (c *blake2sHashBenchCircuit) Define(api frontend.API) error {
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		return err
	}

	blake2sChip := blake2s.NewBlake2sChip(api)
	blake2sChip.Blake2s(uapi, c.In[:])

	return nil
}

func BenchmarkBlake2sHash(b *testing.B) {
	proofSystem := "plonk"

	// prepare the circuit and witness used in the unit test
	circuit := &blake2sHashBenchCircuit{}

	var builder frontend.NewBuilder
	switch proofSystem {
	case "plonk":
		builder = scs.NewBuilder
	case "groth16":
		builder = r1cs.NewBuilder
	default:
		fmt.Println("Please provide a valid proof system to benchmark, we only support plonk and groth16")
		os.Exit(1)
	}

	// Create a proper witness with initialized U8 values
	var in [128]uints.U8
	for i := range in {
		in[i] = uints.NewU8(uint8(i % 256)) // Fill with test data
	}
	witness := blake2sHashBenchCircuit{
		In: in,
	}

	var durations durations
	var gates int

	for i := 0; i < b.N; i++ {
		// compile
		t0 := time.Now()
		r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), builder, circuit)
		if err != nil {
			b.Fatalf("compile error: %v", err)
		}
		durations.compile += time.Since(t0).Nanoseconds()
		gates = r1cs.GetNbConstraints()

		switch proofSystem {
		case "plonk":
			plonkProof(r1cs, witness, &durations)
		case "groth16":
			groth16Proof(r1cs, witness, &durations)
		default:
			panic("Please provide a valid proof system to benchmark, we only support plonk and groth16")
		}
	}

	// pretty print summary
	n := int64(b.N)
	avg := func(ns int64) time.Duration { return time.Duration(ns / n) }
	b.Logf("Proof system: %s", proofSystem)
	b.Logf("Circuit constraints: %d", gates)
	b.Logf("Compile: %s | Setup: %s | Prove: %s | Verify: %s",
		avg(durations.compile), avg(durations.setup), avg(durations.prove), avg(durations.verify))
}

func plonkProof(r1cs constraint.ConstraintSystem, witness blake2sHashBenchCircuit, durations *durations) {
	var pk plonk.ProvingKey
	var vk plonk.VerifyingKey

	// setup
	t0 := time.Now()
	srs, srsLagrange, err := unsafekzg.NewSRS(r1cs, unsafekzg.WithFSCache())
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	pk, vk, err = plonk.Setup(r1cs, srs, srsLagrange)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	durations.setup += time.Since(t0).Nanoseconds()

	// witness generation and proof generation
	t1 := time.Now()
	w, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	publicWitness, err := w.Public()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	proof, err := plonk.Prove(r1cs, pk, w)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	durations.prove += time.Since(t1).Nanoseconds()

	// verification
	t2 := time.Now()
	err = plonk.Verify(proof, vk, publicWitness)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	durations.verify += time.Since(t2).Nanoseconds()
}

func groth16Proof(r1cs constraint.ConstraintSystem, witness blake2sHashBenchCircuit, durations *durations) {
	// setup
	t0 := time.Now()
	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	durations.setup += time.Since(t0).Nanoseconds()

	// witness generation and proof generatino
	t1 := time.Now()
	w, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	publicWitness, err := w.Public()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	proof, err := groth16.Prove(r1cs, pk, w)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	durations.prove += time.Since(t1).Nanoseconds()

	// verification
	t2 := time.Now()
	if err := groth16.Verify(proof, vk, publicWitness); err != nil {
		fmt.Println("Error in verification:", err)
		os.Exit(1)
	}
	durations.verify += time.Since(t2).Nanoseconds()
}
