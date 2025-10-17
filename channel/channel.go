// This minimal implementation of the Stwo channel API for Blake2s comes from:
// https://github.com/starkware-libs/stwo-cairo/blob/main/stwo_cairo_verifier/crates/verifier_core/src/channel/blake2s.cairo

package channel

import (
	"math/big"

	"github.com/HerodotusDev/stwo-gnark-verifier/blake2s"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/cmp"
	"github.com/consensys/gnark/std/math/uints"
)

type Blake2sHash [8]uints.U32

var blake2sInitialStateWords = [8]uint32{
	0x6b08e647,
	0xbb67ae85,
	0x3c6ef372,
	0xa54ff53a,
	0x510e527f,
	0x9b05688c,
	0x1f83d9ab,
	0x5be0cd19,
}

type ChannelTime struct {
	nChallenges uints.U32
	nSent       uints.U32
}

// incChallenges bumps the number of issued challenges.
func (ct *ChannelTime) incChallenges(uapi *uints.BinaryField[uints.U32]) {
	ct.nChallenges = uapi.Add(ct.nChallenges, uints.NewU32(1))
}

// incSent bumps the counter used for deriving fresh randomness.
func (ct *ChannelTime) incSent(uapi *uints.BinaryField[uints.U32]) {
	ct.nSent = uapi.Add(ct.nSent, uints.NewU32(1))
}

type Channel struct {
	api         frontend.API
	blake2sChip *blake2s.Blake2sChip
	m31Chip     *m31.M31Chip
	uapi        *uints.BinaryField[uints.U32]

	digest      Blake2sHash
	channelTime ChannelTime
}

// ╔══════════════════════════════════╗
// ║           Constructor            ║
// ╚══════════════════════════════════╝

// NewChannel builds a Blake2s transcript channel chip.
func NewChannel(api frontend.API) *Channel {
	blake2sChip := blake2s.NewBlake2sChip(api)
	m31Chip := m31.NewM31Chip(api)
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		panic(err)
	}

	return &Channel{
		api:         api,
		blake2sChip: blake2sChip,
		m31Chip:     m31Chip,
		uapi:        uapi,
		digest:      zeroHash(),
		channelTime: ChannelTime{
			nChallenges: uints.NewU32(0),
			nSent:       uints.NewU32(0),
		},
	}
}

// ╔══════════════════════════════════╗
// ║           Mix Operations         ║
// ╚══════════════════════════════════╝

// MixRoot absorbs a Merkle root into the running transcript digest.
func (c *Channel) MixRoot(root Blake2sHash) {
	msg := c.hashToBytes(c.digest)
	msg = append(msg, c.hashToBytes(root)...)
	c.updateDigest(c.computeDigest(msg))
}

// MixFelts absorbs secure field elements into the digest.
func (c *Channel) MixFelts(felts []m31.QM31) {
	msg := c.hashToBytes(c.digest)
	for _, felt := range felts {
		msg = append(msg, c.qm31ToBytes(felt)...)
	}
	c.updateDigest(c.computeDigest(msg))
}

// MixU64 absorbs a 64-bit nonce by splitting it into two u32 words.
func (c *Channel) MixU64(nonce uints.U64) {
	lo := c.uapi.PackLSB(nonce[0], nonce[1], nonce[2], nonce[3])
	hi := c.uapi.PackLSB(nonce[4], nonce[5], nonce[6], nonce[7])
	c.MixU32s([]uints.U32{lo, hi})
}

// MixU32s absorbs a slice of u32 values into the digest.
func (c *Channel) MixU32s(data []uints.U32) {
	msg := c.hashToBytes(c.digest)
	for _, value := range data {
		msg = append(msg, c.uapi.UnpackLSB(value)...)
	}
	c.updateDigest(c.computeDigest(msg))
}

// ╔══════════════════════════════════╗
// ║           Random Draws           ║
// ╚══════════════════════════════════╝

// DrawFelt samples a single QM31 element from the channel.
func (c *Channel) DrawFelt() m31.QM31 {
	felts := c.drawRandomBaseFelts()
	return m31.NewQM31FromComponents(felts[0], felts[1], felts[2], felts[3])
}

// DrawFelts samples n QM31 elements, drawing base-field limbs in pairs.
func (c *Channel) DrawFelts(n int) []m31.QM31 {
	if n <= 0 {
		return nil
	}

	res := make([]m31.QM31, 0, n)
	for len(res) < n {
		base := c.drawRandomBaseFelts()
		res = append(res, m31.NewQM31FromComponents(base[0], base[1], base[2], base[3]))
		if len(res) == n {
			break
		}
		res = append(res, m31.NewQM31FromComponents(base[4], base[5], base[6], base[7]))
	}

	return res
}

// DrawRandomBytes exposes the next 32 pseudorandom bytes from the channel.
func (c *Channel) DrawRandomBytes() []uints.U8 {
	words := c.drawRandomWords()
	bytes := make([]uints.U8, 0, 32)
	for _, word := range words {
		bytes = append(bytes, c.uapi.UnpackLSB(word)...)
	}
	return bytes
}

// ╔══════════════════════════════════╗
// ║        Proof of Work Checks      ║
// ╚══════════════════════════════════╝

// MixAndCheckPowNonce mixes a nonce and checks the leading zero bits.
func (c *Channel) MixAndCheckPowNonce(nBits uints.U32, nonce uints.U64) frontend.Variable {
	c.MixU64(nonce)
	return checkProofOfWork(c.api, c.uapi, c.digest, nBits)
}

// checkProofOfWork verifies that the digest has at least nBits leading zeros.
// It is assumed that nBits is a circuit variable (uints.U32).
func checkProofOfWork(api frontend.API, uapi *uints.BinaryField[uints.U32], digest Blake2sHash, nBits uints.U32) frontend.Variable {
	comparator := cmp.NewBoundedComparator(api, big.NewInt(256), false)

	nValue := uapi.ToValue(nBits)
	comparator.AssertIsLessEq(frontend.Variable(0), nValue)
	comparator.AssertIsLessEq(nValue, frontend.Variable(256))

	// Expand digest into a 256-bit MSB-first view.
	bits := make([]frontend.Variable, 0, 256)
	for wordIdx := len(digest) - 1; wordIdx >= 0; wordIdx-- {
		wordVal := uapi.ToValue(digest[wordIdx])
		wordBits := api.ToBinary(wordVal, 32)
		for bitIdx := 31; bitIdx >= 0; bitIdx-- {
			bits = append(bits, wordBits[bitIdx])
		}
	}

	if len(bits) != 256 {
		panic("unexpected digest size")
	}

	violations := frontend.Variable(0)
	for idx, bit := range bits {
		requireZero := comparator.IsLess(frontend.Variable(idx), nValue)
		violations = api.Add(violations, api.Mul(bit, requireZero))
	}

	return api.IsZero(violations)
}

// ╔══════════════════════════════════╗
// ║           Helper Methods         ║
// ╚══════════════════════════════════╝

// updateDigest stores the new digest and updates bookkeeping.
func (c *Channel) updateDigest(newDigest Blake2sHash) {
	c.digest = newDigest
	c.channelTime.incChallenges(c.uapi)
}

// drawRandomBaseFelts samples eight base-field elements for QM31 packing.
func (c *Channel) drawRandomBaseFelts() [8]m31.M31 {
	words := c.drawRandomWords()
	var felts [8]m31.M31
	for i, word := range words {
		val := c.uapi.ToValue(word)
		felts[i] = c.m31Chip.FullReduce(m31.NewM31Unchecked(val))
	}
	return felts
}

// drawRandomWords derives a fresh Blake2s hash from the digest and counter.
func (c *Channel) drawRandomWords() Blake2sHash {
	msg := c.hashToBytes(c.digest)
	msg = append(msg, c.uapi.UnpackLSB(c.channelTime.nSent)...)

	zeroWord := uints.NewU32(0)
	for i := 0; i < 7; i++ {
		msg = append(msg, c.uapi.UnpackLSB(zeroWord)...)
	}

	c.channelTime.incSent(c.uapi)

	return c.computeDigest(msg)
}

// hashToBytes flattens a Blake2s hash into a byte slice.
func (c *Channel) hashToBytes(hash Blake2sHash) []uints.U8 {
	bytes := make([]uints.U8, 0, 32)
	for _, word := range hash {
		bytes = append(bytes, c.uapi.UnpackLSB(word)...)
	}
	return bytes
}

// qm31ToBytes encodes a QM31 element as sixteen little-endian bytes.
func (c *Channel) qm31ToBytes(felt m31.QM31) []uints.U8 {
	comps := felt.Components()
	bytes := make([]uints.U8, 0, 16)
	for _, comp := range comps {
		word := c.uapi.ValueOf(comp.Variable())
		bytes = append(bytes, c.uapi.UnpackLSB(word)...)
	}
	return bytes
}

// computeDigest replays the Blake2s state machine on the provided message.
func (c *Channel) computeDigest(msg []uints.U8) Blake2sHash {
	state := newBlake2sState()
	length := len(msg)
	if length == 0 {
		state, _ = c.blake2sChip.Finalize(state)
		return Blake2sHash(state.H)
	}

	headLen := 0
	tailLen := length

	if length >= 64 {
		tailLen = length % 64
		if tailLen == 0 {
			tailLen = 64
		}
		headLen = length - tailLen
		if headLen > 0 {
			state = c.blake2sChip.Update(state, msg[:headLen])
		}
	}

	if tailLen > 0 {
		copy(state.Buf[:tailLen], msg[headLen:])
	}
	state.BufLen = tailLen

	state, _ = c.blake2sChip.Finalize(state)
	return Blake2sHash(state.H)
}

// zeroHash returns the zero-initialized Blake2s hash.
func zeroHash() Blake2sHash {
	var hash Blake2sHash
	for i := range hash {
		hash[i] = uints.NewU32(0)
	}
	return hash
}

// newBlake2sState materializes the canonical Blake2s initial state.
func newBlake2sState() blake2s.Blake2sState {
	var state blake2s.Blake2sState
	for i, word := range blake2sInitialStateWords {
		state.H[i] = uints.NewU32(word)
	}
	state.T[0] = uints.NewU32(0)
	state.T[1] = uints.NewU32(0)
	state.F[0] = uints.NewU32(0)
	state.F[1] = uints.NewU32(0)
	return state
}
