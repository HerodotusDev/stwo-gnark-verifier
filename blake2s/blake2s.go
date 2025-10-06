package blake2s

import (
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

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

type Blake2sChip struct {
	api frontend.API `gnark:"-"`
}

type Blake2sState struct {
	H [8]uints.U32
	T [2]uints.U32
	F [2]uints.U32
}

func NewBlake2sChip(api frontend.API) *Blake2sChip {
	if api.Compiler().Field().Cmp(bn254.ID.ScalarField()) != 0 {
		panic("Gnark compiler not set to BN254 scalar field")
	}

	return &Blake2sChip{api: api}
}

func (c *Blake2sChip) Compress(uapi *uints.BinaryField[uints.U32], state Blake2sState, in [16]uints.U32) Blake2sState {
	var v [16]uints.U32
	var m [16]uints.U32

	// Initialize m
	copy(m[:], in[:])

	// Initialize v
	copy(v[:8], state.H[:])
	v[8] = blake2sIV[0]
	v[9] = blake2sIV[1]
	v[10] = blake2sIV[2]
	v[11] = blake2sIV[3]
	v[12] = uapi.Xor(state.T[0], blake2sIV[4])
	v[13] = uapi.Xor(state.T[1], blake2sIV[5])
	v[14] = uapi.Xor(state.F[0], blake2sIV[6])
	v[15] = uapi.Xor(state.F[1], blake2sIV[7])

	// Rounds
	for r := 0; r < 10; r++ {
		// G(r,0,v[0],v[4],v[8],v[12])
		a, b, c0, d := 0, 4, 8, 12
		v[a] = uapi.Add(v[a], v[b], m[blake2sSigma[r][2*0+0]])
		v[d] = uapi.Lrot(uapi.Xor(v[d], v[a]), -16)
		v[c0] = uapi.Add(v[c0], v[d])
		v[b] = uapi.Lrot(uapi.Xor(v[b], v[c0]), -12)
		v[a] = uapi.Add(v[a], v[b], m[blake2sSigma[r][2*0+1]])
		v[d] = uapi.Lrot(uapi.Xor(v[d], v[a]), -8)
		v[c0] = uapi.Add(v[c0], v[d])
		v[b] = uapi.Lrot(uapi.Xor(v[b], v[c0]), -7)

		// G(r,1,v[1],v[5],v[9],v[13])
		a, b, c0, d = 1, 5, 9, 13
		v[a] = uapi.Add(v[a], v[b], m[blake2sSigma[r][2*1+0]])
		v[d] = uapi.Lrot(uapi.Xor(v[d], v[a]), -16)
		v[c0] = uapi.Add(v[c0], v[d])
		v[b] = uapi.Lrot(uapi.Xor(v[b], v[c0]), -12)
		v[a] = uapi.Add(v[a], v[b], m[blake2sSigma[r][2*1+1]])
		v[d] = uapi.Lrot(uapi.Xor(v[d], v[a]), -8)
		v[c0] = uapi.Add(v[c0], v[d])
		v[b] = uapi.Lrot(uapi.Xor(v[b], v[c0]), -7)

		// G(r,2,v[2],v[6],v[10],v[14])
		a, b, c0, d = 2, 6, 10, 14
		v[a] = uapi.Add(v[a], v[b], m[blake2sSigma[r][2*2+0]])
		v[d] = uapi.Lrot(uapi.Xor(v[d], v[a]), -16)
		v[c0] = uapi.Add(v[c0], v[d])
		v[b] = uapi.Lrot(uapi.Xor(v[b], v[c0]), -12)
		v[a] = uapi.Add(v[a], v[b], m[blake2sSigma[r][2*2+1]])
		v[d] = uapi.Lrot(uapi.Xor(v[d], v[a]), -8)
		v[c0] = uapi.Add(v[c0], v[d])
		v[b] = uapi.Lrot(uapi.Xor(v[b], v[c0]), -7)

		// G(r,3,v[3],v[7],v[11],v[15])
		a, b, c0, d = 3, 7, 11, 15
		v[a] = uapi.Add(v[a], v[b], m[blake2sSigma[r][2*3+0]])
		v[d] = uapi.Lrot(uapi.Xor(v[d], v[a]), -16)
		v[c0] = uapi.Add(v[c0], v[d])
		v[b] = uapi.Lrot(uapi.Xor(v[b], v[c0]), -12)
		v[a] = uapi.Add(v[a], v[b], m[blake2sSigma[r][2*3+1]])
		v[d] = uapi.Lrot(uapi.Xor(v[d], v[a]), -8)
		v[c0] = uapi.Add(v[c0], v[d])
		v[b] = uapi.Lrot(uapi.Xor(v[b], v[c0]), -7)

		// G(r,4,v[0],v[5],v[10],v[15])
		a, b, c0, d = 0, 5, 10, 15
		v[a] = uapi.Add(v[a], v[b], m[blake2sSigma[r][2*4+0]])
		v[d] = uapi.Lrot(uapi.Xor(v[d], v[a]), -16)
		v[c0] = uapi.Add(v[c0], v[d])
		v[b] = uapi.Lrot(uapi.Xor(v[b], v[c0]), -12)
		v[a] = uapi.Add(v[a], v[b], m[blake2sSigma[r][2*4+1]])
		v[d] = uapi.Lrot(uapi.Xor(v[d], v[a]), -8)
		v[c0] = uapi.Add(v[c0], v[d])
		v[b] = uapi.Lrot(uapi.Xor(v[b], v[c0]), -7)

		// G(r,5,v[1],v[6],v[11],v[12])
		a, b, c0, d = 1, 6, 11, 12
		v[a] = uapi.Add(v[a], v[b], m[blake2sSigma[r][2*5+0]])
		v[d] = uapi.Lrot(uapi.Xor(v[d], v[a]), -16)
		v[c0] = uapi.Add(v[c0], v[d])
		v[b] = uapi.Lrot(uapi.Xor(v[b], v[c0]), -12)
		v[a] = uapi.Add(v[a], v[b], m[blake2sSigma[r][2*5+1]])
		v[d] = uapi.Lrot(uapi.Xor(v[d], v[a]), -8)
		v[c0] = uapi.Add(v[c0], v[d])
		v[b] = uapi.Lrot(uapi.Xor(v[b], v[c0]), -7)

		// G(r,6,v[2],v[7],v[8],v[13])
		a, b, c0, d = 2, 7, 8, 13
		v[a] = uapi.Add(v[a], v[b], m[blake2sSigma[r][2*6+0]])
		v[d] = uapi.Lrot(uapi.Xor(v[d], v[a]), -16)
		v[c0] = uapi.Add(v[c0], v[d])
		v[b] = uapi.Lrot(uapi.Xor(v[b], v[c0]), -12)
		v[a] = uapi.Add(v[a], v[b], m[blake2sSigma[r][2*6+1]])
		v[d] = uapi.Lrot(uapi.Xor(v[d], v[a]), -8)
		v[c0] = uapi.Add(v[c0], v[d])
		v[b] = uapi.Lrot(uapi.Xor(v[b], v[c0]), -7)

		// G(r,7,v[3],v[4],v[9],v[14])
		a, b, c0, d = 3, 4, 9, 14
		v[a] = uapi.Add(v[a], v[b], m[blake2sSigma[r][2*7+0]])
		v[d] = uapi.Lrot(uapi.Xor(v[d], v[a]), -16)
		v[c0] = uapi.Add(v[c0], v[d])
		v[b] = uapi.Lrot(uapi.Xor(v[b], v[c0]), -12)
		v[a] = uapi.Add(v[a], v[b], m[blake2sSigma[r][2*7+1]])
		v[d] = uapi.Lrot(uapi.Xor(v[d], v[a]), -8)
		v[c0] = uapi.Add(v[c0], v[d])
		v[b] = uapi.Lrot(uapi.Xor(v[b], v[c0]), -7)

	}

	for i := 0; i < 8; i++ {
		state.H[i] = uapi.Xor(state.H[i], v[i], v[i+8])
	}

	return state
}
