// Tests and vectors come from:
// https://github.com/starkware-libs/stwo-cairo/blob/main/stwo_cairo_verifier/crates/verifier_core/src/channel/blake2s/test.cairo

package channel

import (
	"testing"

	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
)

// ╔══════════════════════════════════╗
// ║          Test Circuits           ║
// ╚══════════════════════════════════╝

// mixFeltsCircuit runs MixFelts and asserts the digest against a fixture.
type mixFeltsCircuit struct {
	Felts    []m31.QM31  `gnark:"-"`
	Expected Blake2sHash `gnark:"-"`
}

func (c *mixFeltsCircuit) Define(api frontend.API) error {
	ch := NewChannel(api)
	ch.MixFelts(c.Felts)
	for i := range c.Expected {
		ch.uapi.AssertEq(ch.digest[i], c.Expected[i])
	}
	return nil
}

// mixU32sCircuit runs MixU32s and checks the digest.
type mixU32sCircuit struct {
	Data     []uints.U32 `gnark:"-"`
	Expected Blake2sHash `gnark:"-"`
}

func (c *mixU32sCircuit) Define(api frontend.API) error {
	ch := NewChannel(api)
	ch.MixU32s(c.Data)
	for i := range c.Expected {
		ch.uapi.AssertEq(ch.digest[i], c.Expected[i])
	}
	return nil
}

// mixU64Circuit runs MixU64 and checks the digest.
type mixU64Circuit struct {
	Nonce    uints.U64   `gnark:"-"`
	Expected Blake2sHash `gnark:"-"`
}

func (c *mixU64Circuit) Define(api frontend.API) error {
	ch := NewChannel(api)
	ch.MixU64(c.Nonce)
	for i := range c.Expected {
		ch.uapi.AssertEq(ch.digest[i], c.Expected[i])
	}
	return nil
}

// checkPowCircuit runs the proof-of-work predicate on a fixed digest.
type checkPowCircuit struct {
	Digest Blake2sHash `gnark:"-"`
}

func (c *checkPowCircuit) Define(api frontend.API) error {
	uapi, _ := uints.New[uints.U32](api)
	checkProofOfWork(api, uapi, c.Digest, 24)
	return nil
}

// drawRandomBytesCircuit captures the first 32 random bytes.
type drawRandomBytesCircuit struct {
	expected []uints.U8 `gnark:"-"`
}

func (c *drawRandomBytesCircuit) Define(api frontend.API) error {
	ch := NewChannel(api)
	bytes := ch.DrawRandomBytes()
	if len(bytes) != len(c.expected) {
		panic("unexpected number of bytes drawn")
	}
	for i := range c.expected {
		api.AssertIsEqual(bytes[i].Val, c.expected[i].Val)
	}
	return nil
}

// drawFeltCircuit samples a single QM31 element.
type drawFeltCircuit struct {
	expected []m31.M31 `gnark:"-"`
}

func (c *drawFeltCircuit) Define(api frontend.API) error {
	ch := NewChannel(api)
	felt := ch.DrawFelt()
	comps := felt.Components()
	if len(c.expected) != len(comps) {
		panic("unexpected felt components")
	}
	for i := range comps {
		api.AssertIsEqual(comps[i].Variable(), c.expected[i].Variable())
	}
	return nil
}

// drawFeltsCircuit samples multiple QM31 elements.
type drawFeltsCircuit struct {
	expected []m31.QM31 `gnark:"-"`
}

func (c *drawFeltsCircuit) Define(api frontend.API) error {
	ch := NewChannel(api)
	felts := ch.DrawFelts(len(c.expected))
	if len(felts) != len(c.expected) {
		panic("unexpected number of felts drawn")
	}
	for i, expFelt := range c.expected {
		comps := felts[i].Components()
		expectedComps := expFelt.Components()
		for j := range comps {
			api.AssertIsEqual(comps[j].Variable(), expectedComps[j].Variable())
		}
	}
	return nil
}

// runCircuit compiles and executes a circuit under Groth16 on BN254.
func runCircuit(t *testing.T, circuit frontend.Circuit) {
	assert := test.NewAssert(t)
	assert.CheckCircuit(circuit,
		test.WithValidAssignment(circuit),
		test.WithCurves(ecc.BN254),
	)
}

func runCircuitExpectFailure(t *testing.T, circuit frontend.Circuit) {
	assert := test.NewAssert(t)
	assert.CheckCircuit(circuit,
		test.WithInvalidAssignment(circuit),
		test.WithCurves(ecc.BN254),
	)
}

// ╔══════════════════════════════════╗
// ║           Mixer Vectors          ║
// ╚══════════════════════════════════╝

// TestMixFeltsWith1Felt mirrors the Cairo single-felt test vector.
func TestMixFeltsWith1Felt(t *testing.T) {
	circuit := &mixFeltsCircuit{
		Felts: newQM31sFromUint([][4]uint64{
			{1, 2, 3, 4},
		}),
		Expected: newHash([8]uint32{
			1586304710, 1167332849, 1688630032, 429142330,
			4001363212, 2013799503, 180553907, 2044853257,
		}),
	}
	runCircuit(t, circuit)
}

// TestMixFeltsWith2Felts mirrors the Cairo two-felt test vector.
func TestMixFeltsWith2Felts(t *testing.T) {
	circuit := &mixFeltsCircuit{
		Felts: newQM31sFromUint([][4]uint64{
			{1, 2, 3, 4},
			{5, 6, 7, 8},
		}),
		Expected: newHash([8]uint32{
			1835698174, 2969628929, 1758616107, 158303712,
			3820231193, 179192886, 4063347398, 3332297509,
		}),
	}
	runCircuit(t, circuit)
}

// TestMixFeltsWith3Felts mirrors the Cairo three-felt test vector.
func TestMixFeltsWith3Felts(t *testing.T) {
	circuit := &mixFeltsCircuit{
		Felts: newQM31sFromUint([][4]uint64{
			{1, 2, 3, 4},
			{5, 6, 7, 8},
			{9, 10, 11, 12},
		}),
		Expected: newHash([8]uint32{
			2116479765, 3227507660, 1737697798, 2518684651,
			1068812914, 1858078313, 1722202885, 2198022752,
		}),
	}
	runCircuit(t, circuit)
}

// TestMixFeltsWith4Felts mirrors the Cairo four-felt test vector.
func TestMixFeltsWith4Felts(t *testing.T) {
	circuit := &mixFeltsCircuit{
		Felts: newQM31sFromUint([][4]uint64{
			{1, 2, 3, 4},
			{5, 6, 7, 8},
			{9, 10, 11, 12},
			{13, 14, 15, 16},
		}),
		Expected: newHash([8]uint32{
			940149128, 1354728945, 2816315586, 1690943110,
			210254904, 3746481728, 1339132640, 3760408575,
		}),
	}
	runCircuit(t, circuit)
}

// TestMixFeltsWith5Felts mirrors the Cairo five-felt test vector.
func TestMixFeltsWith5Felts(t *testing.T) {
	circuit := &mixFeltsCircuit{
		Felts: newQM31sFromUint([][4]uint64{
			{1, 2, 3, 4},
			{5, 6, 7, 8},
			{9, 10, 11, 12},
			{13, 14, 15, 16},
			{17, 18, 19, 20},
		}),
		Expected: newHash([8]uint32{
			3425911356, 1462327982, 3241135902, 4212900065,
			3145879221, 3413011910, 3946733048, 4081152200,
		}),
	}
	runCircuit(t, circuit)
}

// TestMixU64 mirrors the Cairo u64 mixing test vector.
func TestMixU64(t *testing.T) {
	circuit := &mixU64Circuit{
		Nonce: uints.NewU64(0x1111222233334444),
		Expected: newHash([8]uint32{
			0xc13f9ebc, 0x97884ed2, 0x59336d95, 0x24977332,
			0xcdca6b9d, 0x74924d22, 0x4abae704, 0xce6edc77,
		}),
	}
	runCircuit(t, circuit)
}

// TestMixU32s mirrors the Cairo u32 mixing test vector.
func TestMixU32s(t *testing.T) {
	circuit := &mixU32sCircuit{
		Data: uints.NewU32Array([]uint32{1, 2, 3, 4, 5, 6, 7, 8, 9}),
		Expected: newHash([8]uint32{
			0x83769170, 0xb31bbb57, 0xb6da6f34, 0xfad757b3,
			0xe3fbb846, 0x24432e2c, 0x94c2ffa0, 0xc7a1f9cb,
		}),
	}
	runCircuit(t, circuit)
}

// ╔══════════════════════════════════╗
// ║           Draw Vectors           ║
// ╚══════════════════════════════════╝

// TestDrawRandomBytes mirrors the Cairo random-bytes test vector.
func TestDrawRandomBytes(t *testing.T) {
	circuit := &drawRandomBytesCircuit{
		expected: newU8s([]uint8{
			174, 9, 219, 124, 213, 79, 66, 180, 144, 239, 9, 182, 188, 84, 26, 246,
			136, 228, 149, 155, 184, 197, 63, 53, 154, 111, 86, 227, 138, 180, 84, 163,
		}),
	}
	runCircuit(t, circuit)
}

// TestDrawFelt mirrors the Cairo single-felt draw test vector.
func TestDrawFelt(t *testing.T) {
	circuit := &drawFeltCircuit{
		expected: newM31sFromUint([]uint32{2094729646, 876761046, 906620817, 1981437117}),
	}
	runCircuit(t, circuit)
}

// TestDrawFelts mirrors the Cairo multi-felt draw test vector.
func TestDrawFelts(t *testing.T) {
	circuit := &drawFeltsCircuit{
		expected: newQM31sFromUint([][4]uint32{
			{2094729646, 876761046, 906620817, 1981437117},
			{462808201, 893371832, 1666609051, 592753803},
			{2092874317, 1414799646, 202729759, 1138457893},
			{740261418, 1566411288, 1094134286, 1085813917},
			{1782652641, 591937235, 375882621, 687600507},
			{417708784, 676515713, 1053713500, 313648782},
			{1896458727, 242850046, 267152034, 827396985},
			{1959202869, 765813487, 1783334404, 305015811},
		}),
	}
	runCircuit(t, circuit)
}

// ╔══════════════════════════════════╗
// ║         Proof-of-Work Vectors    ║
// ╚══════════════════════════════════╝

// TestCheckProofOfWork mirrors the Cairo PoW success case.
func TestCheckProofOfWork(t *testing.T) {
	circuit := &checkPowCircuit{
		Digest: newHash([8]uint32{0, 0, 0, 0, 0, 0, 0, 0x00000080}),
	}
	runCircuit(t, circuit)
}

// TestCheckProofOfWorkInvalidBits mirrors the Cairo PoW failure case.
func TestCheckProofOfWorkInvalidBits(t *testing.T) {
	circuit := &checkPowCircuit{
		Digest: newHash([8]uint32{0, 0, 0, 0, 0, 0, 0, 0x01000000}),
	}
	runCircuitExpectFailure(t, circuit)
}

// newHash converts a u32 fixture into a Blake2sHash value.
func newHash(values [8]uint32) Blake2sHash {
	var res Blake2sHash
	for i, v := range values {
		res[i] = uints.NewU32(v)
	}
	return res
}

// ╔══════════════════════════════════╗
// ║         Helper Functions         ║
// ╚══════════════════════════════════╝

// newQM31sFromUint converts a 2x2 uint64 grid into a QM31 if the layout is valid.
func newQM31sFromUint[T ~uint32 | ~uint64](values [][4]T) []m31.QM31 {
	felts := make([]m31.QM31, len(values))
	for i, comps := range values {
		felts[i] = m31.NewQM31Unchecked(uint64(comps[0]), uint64(comps[1]), uint64(comps[2]), uint64(comps[3]))
	}
	return felts
}

// newM31sFromUint converts a slice of uint32 or uint64 into a slice of M31.
func newM31sFromUint[T ~uint32 | ~uint64](values []T) []m31.M31 {
	res := make([]m31.M31, len(values))
	for i, v := range values {
		res[i] = m31.NewM31Unchecked(uint64(v))
	}
	return res
}

func newU8s(values []uint8) []uints.U8 {
	return uints.NewU8Array(values)
}
