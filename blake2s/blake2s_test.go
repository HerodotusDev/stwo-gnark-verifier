package blake2s_test

import (
	"testing"
	"time"

	"github.com/HerodotusDev/stwo-gnark-verifier/blake2s"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
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

type blake2sHashBenchCircuit struct {
	In [64]uints.U8
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
	// prepare the circuit and witness used in the unit test
	circuit := &blake2sHashBenchCircuit{}

	// Create a proper witness with initialized U8 values
	var in [64]uints.U8
	for i := range in {
		in[i] = uints.NewU8(uint8(i % 256)) // Fill with test data
	}
	witness := blake2sHashBenchCircuit{
		In: in,
	}

	var totalCompile, totalSetup, totalProve int64
	var gates int

	for i := 0; i < b.N; i++ {
		// compile
		t0 := time.Now()
		ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
		if err != nil {
			b.Fatalf("compile error: %v", err)
		}
		totalCompile += time.Since(t0).Nanoseconds()
		gates = ccs.GetNbConstraints()

		// setup
		t1 := time.Now()
		pk, _, err := groth16.Setup(ccs)
		if err != nil {
			b.Fatalf("setup error: %v", err)
		}
		totalSetup += time.Since(t1).Nanoseconds()

		// witness generation (private + public)
		t2 := time.Now()
		w, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())
		if err != nil {
			b.Fatalf("witness error: %v", err)
		}
		_, err = w.Public()
		if err != nil {
			b.Fatalf("public witness error: %v", err)
		}

		// proving
		if _, err := groth16.Prove(ccs, pk, w); err != nil {
			b.Fatalf("prove error: %v", err)
		}
		totalProve += time.Since(t2).Nanoseconds()
	}

	// pretty print summary
	n := int64(b.N)
	avg := func(ns int64) time.Duration { return time.Duration(ns / n) }
	b.Logf("Blake2s(\"abc\") constraints: %d", gates)
	b.Logf("Compile: %s | Setup: %s | Prove: %s",
		avg(totalCompile), avg(totalSetup), avg(totalProve))
}
