package blake2s

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/cmp"
	"github.com/consensys/gnark/std/math/uints"
)

var BLAKE2S_BLOCKBYTES = uints.NewU32(64)
var absDiffUpp = big.NewInt(1<<32 - 1)

var blake2sIV = [8]uints.U32{
	uints.NewU32(0x6A09E667),
	uints.NewU32(0xBB67AE85),
	uints.NewU32(0x3C6EF372),
	uints.NewU32(0xA54FF53A),
	uints.NewU32(0x510E527F),
	uints.NewU32(0x9B05688C),
	uints.NewU32(0x1F83D9AB),
	uints.NewU32(0x5BE0CD19),
}

var blake2sSigma = [10][16]int{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
	{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
	{7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
	{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
	{2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
	{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
	{13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
	{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
	{10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
}

// Blake2s initial state (outlen = 32 bytes)
var blake2sInitialState = Blake2sState{
	H: [8]uints.U32{
		uints.NewU32(0x6b08e647), // blake2sIV[0] ^ PARAMS (see specification)
		blake2sIV[1],
		blake2sIV[2],
		blake2sIV[3],
		blake2sIV[4],
		blake2sIV[5],
		blake2sIV[6],
		blake2sIV[7],
	},
	T: [2]uints.U32{
		uints.NewU32(0),
		uints.NewU32(0),
	},
	F: [2]uints.U32{
		uints.NewU32(0),
		uints.NewU32(0),
	},
}

type Blake2sChip struct {
	api  frontend.API                  `gnark:"-"`
	uapi *uints.BinaryField[uints.U32] `gnark:"-"`
}

type Blake2sState struct {
	H [8]uints.U32
	T [2]uints.U32
	F [2]uints.U32

	// byte buffer for streaming update (0..64 bytes)
	Buf    [64]uints.U8
	BufLen int
}

func NewBlake2sChip(api frontend.API) *Blake2sChip {
	if api.Compiler().Field().Cmp(bn254.ID.ScalarField()) != 0 {
		panic("Gnark compiler not set to BN254 scalar field")
	}

	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		panic(err)
	}

	return &Blake2sChip{api: api, uapi: uapi}
}

func (c *Blake2sChip) Blake2s(msg []uints.U8) Blake2sState {
	S := blake2sInitialState
	S = c.Update(S, msg)
	S, _ = c.Finalize(S)
	return S
}

func (c *Blake2sChip) Update(state Blake2sState, msg []uints.U8) Blake2sState {
	if len(msg) == 0 {
		return state
	}

	// Comparator for carry on 32-bit counter increment
	// |state.T[0] - BLAKE2S_BLOCKBYTES| <= 2^32-1
	less := cmp.NewBoundedComparator(c.api, absDiffUpp, false)

	// Increment t by 64 bytes with carry into t[1]
	incCounter := func() {
		newT0 := c.uapi.Add(state.T[0], BLAKE2S_BLOCKBYTES)
		carry := less.IsLess(c.uapi.ToValue(newT0), c.uapi.ToValue(state.T[0]))
		state.T[0] = newT0
		state.T[1] = c.uapi.Add(state.T[1], c.uapi.ValueOf(carry))
	}

	// Fill existing buffer to 64 bytes if possible
	if state.BufLen > 0 {
		fill := 64 - state.BufLen
		if len(msg) > fill {
			// Copy fill bytes of msg to buffer
			copy(state.Buf[state.BufLen:], msg[:fill])
			incCounter()
			// Pack 64 bytes into 16 u32s
			var block [16]uints.U32
			for w := range 16 {
				base := 4 * w
				block[w] = c.uapi.PackLSB(state.Buf[base : base+4]...)
			}
			// Compress buffered 64-byte block
			state = c.Compress(state, block)
			// Reset buffer and drop processed bytes from msg
			state.BufLen = 0
			msg = msg[fill:]
		} else {
			// Buffer msg if it doesn't fill it
			copy(state.Buf[state.BufLen:state.BufLen+len(msg)], msg)
			state.BufLen += len(msg)
			return state
		}
	}

	// Process full 64-byte chunks directly
	i := 0
	for i+64 <= len(msg) {
		var block [16]uints.U32
		for w := range 16 {
			off := i + 4*w
			block[w] = c.uapi.PackLSB(msg[off : off+4]...)
		}
		incCounter()
		state = c.Compress(state, block)
		i += 64
	}

	// Buffer remaining tail bytes
	if i < len(msg) {
		rem := len(msg) - i
		copy(state.Buf[:rem], msg[i:])
		state.BufLen = rem
	}

	return state
}

func (c *Blake2sChip) Compress(state Blake2sState, in [16]uints.U32) Blake2sState {
	var v [16]uints.U32
	var m [16]uints.U32

	// Initialize m to in
	copy(m[:], in[:])

	// Initialize v
	copy(v[:8], state.H[:])
	v[8] = blake2sIV[0]
	v[9] = blake2sIV[1]
	v[10] = blake2sIV[2]
	v[11] = blake2sIV[3]
	v[12] = c.uapi.Xor(state.T[0], blake2sIV[4])
	v[13] = c.uapi.Xor(state.T[1], blake2sIV[5])
	v[14] = c.uapi.Xor(state.F[0], blake2sIV[6])
	v[15] = c.uapi.Xor(state.F[1], blake2sIV[7])

	// Rounds
	for r := range 10 {
		// G(r,0,v[0],v[4],v[8],v[12])
		a, b, c0, d := 0, 4, 8, 12
		v[a] = c.uapi.Add(v[a], v[b], m[blake2sSigma[r][2*0+0]])
		v[d] = c.uapi.Lrot(c.uapi.Xor(v[d], v[a]), -16)
		v[c0] = c.uapi.Add(v[c0], v[d])
		v[b] = c.uapi.Lrot(c.uapi.Xor(v[b], v[c0]), -12)
		v[a] = c.uapi.Add(v[a], v[b], m[blake2sSigma[r][2*0+1]])
		v[d] = c.uapi.Lrot(c.uapi.Xor(v[d], v[a]), -8)
		v[c0] = c.uapi.Add(v[c0], v[d])
		v[b] = c.uapi.Lrot(c.uapi.Xor(v[b], v[c0]), -7)

		// G(r,1,v[1],v[5],v[9],v[13])
		a, b, c0, d = 1, 5, 9, 13
		v[a] = c.uapi.Add(v[a], v[b], m[blake2sSigma[r][2*1+0]])
		v[d] = c.uapi.Lrot(c.uapi.Xor(v[d], v[a]), -16)
		v[c0] = c.uapi.Add(v[c0], v[d])
		v[b] = c.uapi.Lrot(c.uapi.Xor(v[b], v[c0]), -12)
		v[a] = c.uapi.Add(v[a], v[b], m[blake2sSigma[r][2*1+1]])
		v[d] = c.uapi.Lrot(c.uapi.Xor(v[d], v[a]), -8)
		v[c0] = c.uapi.Add(v[c0], v[d])
		v[b] = c.uapi.Lrot(c.uapi.Xor(v[b], v[c0]), -7)

		// G(r,2,v[2],v[6],v[10],v[14])
		a, b, c0, d = 2, 6, 10, 14
		v[a] = c.uapi.Add(v[a], v[b], m[blake2sSigma[r][2*2+0]])
		v[d] = c.uapi.Lrot(c.uapi.Xor(v[d], v[a]), -16)
		v[c0] = c.uapi.Add(v[c0], v[d])
		v[b] = c.uapi.Lrot(c.uapi.Xor(v[b], v[c0]), -12)
		v[a] = c.uapi.Add(v[a], v[b], m[blake2sSigma[r][2*2+1]])
		v[d] = c.uapi.Lrot(c.uapi.Xor(v[d], v[a]), -8)
		v[c0] = c.uapi.Add(v[c0], v[d])
		v[b] = c.uapi.Lrot(c.uapi.Xor(v[b], v[c0]), -7)

		// G(r,3,v[3],v[7],v[11],v[15])
		a, b, c0, d = 3, 7, 11, 15
		v[a] = c.uapi.Add(v[a], v[b], m[blake2sSigma[r][2*3+0]])
		v[d] = c.uapi.Lrot(c.uapi.Xor(v[d], v[a]), -16)
		v[c0] = c.uapi.Add(v[c0], v[d])
		v[b] = c.uapi.Lrot(c.uapi.Xor(v[b], v[c0]), -12)
		v[a] = c.uapi.Add(v[a], v[b], m[blake2sSigma[r][2*3+1]])
		v[d] = c.uapi.Lrot(c.uapi.Xor(v[d], v[a]), -8)
		v[c0] = c.uapi.Add(v[c0], v[d])
		v[b] = c.uapi.Lrot(c.uapi.Xor(v[b], v[c0]), -7)

		// G(r,4,v[0],v[5],v[10],v[15])
		a, b, c0, d = 0, 5, 10, 15
		v[a] = c.uapi.Add(v[a], v[b], m[blake2sSigma[r][2*4+0]])
		v[d] = c.uapi.Lrot(c.uapi.Xor(v[d], v[a]), -16)
		v[c0] = c.uapi.Add(v[c0], v[d])
		v[b] = c.uapi.Lrot(c.uapi.Xor(v[b], v[c0]), -12)
		v[a] = c.uapi.Add(v[a], v[b], m[blake2sSigma[r][2*4+1]])
		v[d] = c.uapi.Lrot(c.uapi.Xor(v[d], v[a]), -8)
		v[c0] = c.uapi.Add(v[c0], v[d])
		v[b] = c.uapi.Lrot(c.uapi.Xor(v[b], v[c0]), -7)

		// G(r,5,v[1],v[6],v[11],v[12])
		a, b, c0, d = 1, 6, 11, 12
		v[a] = c.uapi.Add(v[a], v[b], m[blake2sSigma[r][2*5+0]])
		v[d] = c.uapi.Lrot(c.uapi.Xor(v[d], v[a]), -16)
		v[c0] = c.uapi.Add(v[c0], v[d])
		v[b] = c.uapi.Lrot(c.uapi.Xor(v[b], v[c0]), -12)
		v[a] = c.uapi.Add(v[a], v[b], m[blake2sSigma[r][2*5+1]])
		v[d] = c.uapi.Lrot(c.uapi.Xor(v[d], v[a]), -8)
		v[c0] = c.uapi.Add(v[c0], v[d])
		v[b] = c.uapi.Lrot(c.uapi.Xor(v[b], v[c0]), -7)

		// G(r,6,v[2],v[7],v[8],v[13])
		a, b, c0, d = 2, 7, 8, 13
		v[a] = c.uapi.Add(v[a], v[b], m[blake2sSigma[r][2*6+0]])
		v[d] = c.uapi.Lrot(c.uapi.Xor(v[d], v[a]), -16)
		v[c0] = c.uapi.Add(v[c0], v[d])
		v[b] = c.uapi.Lrot(c.uapi.Xor(v[b], v[c0]), -12)
		v[a] = c.uapi.Add(v[a], v[b], m[blake2sSigma[r][2*6+1]])
		v[d] = c.uapi.Lrot(c.uapi.Xor(v[d], v[a]), -8)
		v[c0] = c.uapi.Add(v[c0], v[d])
		v[b] = c.uapi.Lrot(c.uapi.Xor(v[b], v[c0]), -7)

		// G(r,7,v[3],v[4],v[9],v[14])
		a, b, c0, d = 3, 4, 9, 14
		v[a] = c.uapi.Add(v[a], v[b], m[blake2sSigma[r][2*7+0]])
		v[d] = c.uapi.Lrot(c.uapi.Xor(v[d], v[a]), -16)
		v[c0] = c.uapi.Add(v[c0], v[d])
		v[b] = c.uapi.Lrot(c.uapi.Xor(v[b], v[c0]), -12)
		v[a] = c.uapi.Add(v[a], v[b], m[blake2sSigma[r][2*7+1]])
		v[d] = c.uapi.Lrot(c.uapi.Xor(v[d], v[a]), -8)
		v[c0] = c.uapi.Add(v[c0], v[d])
		v[b] = c.uapi.Lrot(c.uapi.Xor(v[b], v[c0]), -7)

	}

	for i := range 8 {
		state.H[i] = c.uapi.Xor(state.H[i], v[i], v[i+8])
	}

	return state
}

func (c *Blake2sChip) Finalize(state Blake2sState) (Blake2sState, [32]uints.U8) {
	// Increment counter by remaining bytes (BufLen)
	if state.BufLen > 0 {
		// Comparator for carry on 32-bit counter increment
		less := cmp.NewBoundedComparator(c.api, absDiffUpp, false)

		inc := uints.NewU32(uint32(state.BufLen))
		newT0 := c.uapi.Add(state.T[0], inc)
		carry := less.IsLess(c.uapi.ToValue(newT0), c.uapi.ToValue(state.T[0]))
		state.T[0] = newT0
		state.T[1] = c.uapi.Add(state.T[1], c.uapi.ValueOf(carry))
	}

	// Set last block flag
	state.F[0] = uints.NewU32(0xFFFFFFFF)

	// Build padded 64-byte block from buffer; ensure zero bytes are proper constants
	var blockBytes [64]uints.U8
	copy(blockBytes[:state.BufLen], state.Buf[:state.BufLen])
	for i := state.BufLen; i < 64; i++ {
		blockBytes[i] = uints.NewU8(0)
	}

	// Pack into 16 little-endian u32 words
	var block [16]uints.U32
	for w := range 16 {
		off := 4 * w
		block[w] = c.uapi.PackLSB(blockBytes[off : off+4]...)
	}

	// Compress final block
	state = c.Compress(state, block)

	// Produce 32-byte digest from state.H (little-endian words)
	var out [32]uints.U8
	for i := range 8 {
		bs := c.uapi.UnpackLSB(state.H[i])
		out[4*i+0] = bs[0]
		out[4*i+1] = bs[1]
		out[4*i+2] = bs[2]
		out[4*i+3] = bs[3]
	}

	return state, out
}
