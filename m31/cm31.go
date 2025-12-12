package m31

import (
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
)

func init() {
	solver.RegisterHint(CM31InverseHint)

}

// ╔══════════════════════════════════╗
// ║        CM31 Field Element        ║
// ╚══════════════════════════════════╝

type CM31 struct {
	Real M31
	Imag M31
}

// ╔══════════════════════════════════╗
// ║          CM31 Arithmetics        ║
// ╚══════════════════════════════════╝

// CmAdd adds two cm31 elements.
func (q *QM31Chip) CmAdd(x, y CM31) CM31 {
	return CM31{
		Real: q.m31.Add(x.Real, y.Real),
		Imag: q.m31.Add(x.Imag, y.Imag),
	}
}

// cmAddUnchecked adds two cm31 elements without reducing the result.
func (q *QM31Chip) cmAddUnchecked(x, y CM31) CM31 {
	return CM31{
		Real: q.m31.AddUnchecked(x.Real, y.Real),
		Imag: q.m31.AddUnchecked(x.Imag, y.Imag),
	}
}

// CmSub subtracts two cm31 elements.
func (q *QM31Chip) CmSub(x, y CM31) CM31 {
	return CM31{
		Real: q.m31.Sub(x.Real, y.Real),
		Imag: q.m31.Sub(x.Imag, y.Imag),
	}
}

// CmMul multiplies two cm31 elements.
func (q *QM31Chip) CmMul(x, y CM31) CM31 {
	ar := q.m31.Mul(x.Real, y.Real)
	bi := q.m31.Mul(x.Imag, y.Imag)
	r := q.m31.Sub(ar, bi)

	ai := q.m31.Mul(x.Real, y.Imag)
	br := q.m31.Mul(x.Imag, y.Real)
	i := q.m31.Add(ai, br)

	return CM31{Real: r, Imag: i}
}

// cmMulUnchecked multiplies two cm31 elements without reducing the result.
func (q *QM31Chip) cmMulUnchecked(x, y CM31) CM31 {
	ar := q.m31.MulUnchecked(x.Real, y.Real)
	bi := q.m31.MulUnchecked(x.Imag, y.Imag)
	r := q.m31.SubUnchecked(ar, bi)

	ai := q.m31.MulUnchecked(x.Real, y.Imag)
	br := q.m31.MulUnchecked(x.Imag, y.Real)
	i := q.m31.AddUnchecked(ai, br)

	return CM31{Real: r, Imag: i}
}

// cmMulByRUnchecked multiplies a cm31 element by R without reducing the result.
func (q *QM31Chip) cmMulByRUnchecked(x CM31) CM31 {
	twoReal := q.m31.AddUnchecked(x.Real, x.Real)
	twoImag := q.m31.AddUnchecked(x.Imag, x.Imag)

	real := q.m31.SubUnchecked(twoReal, x.Imag)
	imag := q.m31.AddUnchecked(twoImag, x.Real)
	return CM31{Real: real, Imag: imag}
}

// CmSubM31 subtracts an M31 element from a cm31 element.
func (q *QM31Chip) CmSubM31(x CM31, m M31) CM31 {
	return CM31{
		Real: q.m31.Sub(x.Real, m),
		Imag: x.Imag,
	}
}

// ╔══════════════════════════════════╗
// ║          CM31 Inversion          ║
// ╚══════════════════════════════════╝

// CM31Inverse inverts a CM31 element.
func (q *QM31Chip) CM31Inverse(x CM31) CM31 {
	api := q.m31.api
	hintInputs := []frontend.Variable{x.Real.Limb, x.Imag.Limb}
	hintOutputs, err := api.Compiler().NewHint(CM31InverseHint, 2, hintInputs...)
	if err != nil {
		panic(err)
	}

	inv := CM31{
		Real: NewM31Unchecked(hintOutputs[0]),
		Imag: NewM31Unchecked(hintOutputs[1]),
	}

	q.m31.RangeCheck(inv.Real)
	q.m31.RangeCheck(inv.Imag)

	isZero := api.IsZero(x.Real.Limb)
	isZero = api.Mul(isZero, api.IsZero(x.Imag.Limb))
	hasInv := api.Sub(1, isZero)

	product := q.CmMul(x, inv)
	one := CM31{Real: One(), Imag: Zero()}

	api.AssertIsEqual(api.Select(hasInv, product.Real.Limb, one.Real.Limb), one.Real.Limb)
	api.AssertIsEqual(api.Select(hasInv, product.Imag.Limb, one.Imag.Limb), one.Imag.Limb)

	return inv
}

// CM31InverseHint computes the inverse of a CM31 element.
func CM31InverseHint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	if len(inputs) != 2 {
		panic("CM31InverseHint expects 2 inputs")
	}
	if len(results) != 2 {
		panic("CM31InverseHint expects 2 results")
	}

	vals := [2]uint64{}
	for i, in := range inputs {
		if in.Sign() < 0 || in.Cmp(PrimeBigInt) >= 0 {
			panic("input not in field")
		}
		vals[i] = in.Uint64()
		if results[i] == nil {
			results[i] = new(big.Int)
		}
		results[i].SetUint64(0)
	}
	if vals[0]|vals[1] == 0 {
		return nil
	}

	mod := uint64(Prime)
	add := func(a, b uint64) uint64 {
		c := a + b
		if c >= mod {
			c -= mod
		}
		return c
	}
	neg := func(a uint64) uint64 {
		if a == 0 {
			return 0
		}
		return mod - a
	}
	mul := func(a, b uint64) uint64 {
		return (a * b) % mod
	}

	den := add(mul(vals[0], vals[0]), mul(vals[1], vals[1]))
	denInv := pow2147483645M31(den)
	results[0].SetUint64(mul(vals[0], denInv))
	results[1].SetUint64(mul(neg(vals[1]), denInv))
	return nil
}
