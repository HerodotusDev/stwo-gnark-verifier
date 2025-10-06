package blake2s_test

import (
	"testing"

	"github.com/HerodotusDev/stwo-gnark-verifier/blake2s"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
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
		uints.NewU32(3),
		uints.NewU32(0),
	}
	testStateF = [2]uints.U32{
		uints.NewU32(4294967295),
		uints.NewU32(0),
	}
	testIn = [16]uints.U32{
		uints.NewU32(0x00636261),
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

type blake2sCircuit struct {
	StateH    [8]uints.U32
	StateT    [2]uints.U32
	StateF    [2]uints.U32
	In        [16]uints.U32
	ExpectedH [8]uints.U32
}

func (c *blake2sCircuit) Define(api frontend.API) error {
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
	witness := blake2sCircuit{
		StateH:    testStateH,
		StateT:    testStateT,
		StateF:    testStateF,
		In:        testIn,
		ExpectedH: testExpectedH,
	}
	assert := test.NewAssert(t)
	assert.ProverSucceeded(&blake2sCircuit{}, &witness,
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16),
		test.NoProverChecks(),
		test.NoFuzzing())
}
