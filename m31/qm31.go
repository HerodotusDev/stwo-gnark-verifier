package m31

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
)

func init() {
	solver.RegisterHint(QM31InverseHint)
}

// ╔══════════════════════════════════╗
// ║        QM31 Field Element        ║
// ╚══════════════════════════════════╝

// QM31 represents an element of the quadratic extension over CM31: a + u b.
type QM31 struct {
	aReal M31
	aImag M31
	bReal M31
	bImag M31
}

type cm31 struct {
	real M31
	imag M31
}

// ╔══════════════════════════════════╗
// ║             QM31 Chip            ║
// ╚══════════════════════════════════╝

// QM31Chip exposes arithmetic for QM31 elements.
type QM31Chip struct {
	m31 *M31Chip
}

// NewQM31Chip builds a QM31 chip from the underlying M31 chip.
func NewQM31Chip(m31 *M31Chip) *QM31Chip {
	return &QM31Chip{m31: m31}
}

func (q *QM31Chip) FromM31(m M31) QM31 {
	return QM31{
		aReal: m,
		aImag: Zero(),
		bReal: Zero(),
		bImag: Zero(),
	}
}

// Zero returns the additive identity.
func (q *QM31Chip) Zero() QM31 {
	return QM31{
		aReal: Zero(),
		aImag: Zero(),
		bReal: Zero(),
		bImag: Zero(),
	}
}

// One returns the multiplicative identity.
func (q *QM31Chip) One() QM31 {
	return QM31{
		aReal: One(),
		aImag: Zero(),
		bReal: Zero(),
		bImag: Zero(),
	}
}

// ╔══════════════════════════════════╗
// ║          QM31 Arithmetics        ║
// ╚══════════════════════════════════╝

// Add computes x + y.
func (q *QM31Chip) Add(x, y QM31) QM31 {
	return QM31{
		aReal: q.m31.Add(x.aReal, y.aReal),
		aImag: q.m31.Add(x.aImag, y.aImag),
		bReal: q.m31.Add(x.bReal, y.bReal),
		bImag: q.m31.Add(x.bImag, y.bImag),
	}
}

// AddUnchecked computes x + y without reducing the result.
func (q *QM31Chip) AddUnchecked(x, y QM31) QM31 {
	return QM31{
		aReal: q.m31.AddUnchecked(x.aReal, y.aReal),
		aImag: q.m31.AddUnchecked(x.aImag, y.aImag),
		bReal: q.m31.AddUnchecked(x.bReal, y.bReal),
		bImag: q.m31.AddUnchecked(x.bImag, y.bImag),
	}
}

// Sub computes x - y.
func (q *QM31Chip) Sub(x, y QM31) QM31 {
	return QM31{
		aReal: q.m31.Sub(x.aReal, y.aReal),
		aImag: q.m31.Sub(x.aImag, y.aImag),
		bReal: q.m31.Sub(x.bReal, y.bReal),
		bImag: q.m31.Sub(x.bImag, y.bImag),
	}
}

// SubUnchecked computes x - y without reducing.
func (q *QM31Chip) SubUnchecked(x, y QM31) QM31 {
	return QM31{
		aReal: q.m31.SubUnchecked(x.aReal, y.aReal),
		aImag: q.m31.SubUnchecked(x.aImag, y.aImag),
		bReal: q.m31.SubUnchecked(x.bReal, y.bReal),
		bImag: q.m31.SubUnchecked(x.bImag, y.bImag),
	}
}

// Neg returns -x.
func (q *QM31Chip) Neg(x QM31) QM31 {
	return QM31{
		aReal: q.m31.Neg(x.aReal),
		aImag: q.m31.Neg(x.aImag),
		bReal: q.m31.Neg(x.bReal),
		bImag: q.m31.Neg(x.bImag),
	}
}

// Mul computes (a + u b)(c + u d) with u^2 = 2 + i.
func (q *QM31Chip) Mul(lhs, rhs QM31) QM31 {
	resultUnreduced := q.MulUnchecked(lhs, rhs)
	return QM31{
		aReal: q.m31.ReduceWithMaxBits(resultUnreduced.aReal, 64),
		aImag: q.m31.ReduceWithMaxBits(resultUnreduced.aImag, 64),
		bReal: q.m31.ReduceWithMaxBits(resultUnreduced.bReal, 64),
		bImag: q.m31.ReduceWithMaxBits(resultUnreduced.bImag, 64),
	}
}

// MulUnchecked multiplies without reducing intermediate terms.
func (q *QM31Chip) MulUnchecked(lhs, rhs QM31) QM31 {
	a := cm31{lhs.aReal, lhs.aImag}
	b := cm31{lhs.bReal, lhs.bImag}
	c := cm31{rhs.aReal, rhs.aImag}
	d := cm31{rhs.bReal, rhs.bImag}

	ac := q.cmMulUnchecked(a, c)
	bd := q.cmMulUnchecked(b, d)
	rbd := q.cmMulByRUnchecked(bd)
	ad := q.cmMulUnchecked(a, d)
	bc := q.cmMulUnchecked(b, c)

	A := q.cmAddUnchecked(ac, rbd)
	B := q.cmAddUnchecked(ad, bc)

	return QM31{
		aReal: A.real,
		aImag: A.imag,
		bReal: B.real,
		bImag: B.imag,
	}
}

// MulM31 multiplies by a base M31 element.
func (q *QM31Chip) MulM31(x QM31, m M31) QM31 {
	return QM31{
		aReal: q.m31.Mul(x.aReal, m),
		aImag: q.m31.Mul(x.aImag, m),
		bReal: q.m31.Mul(x.bReal, m),
		bImag: q.m31.Mul(x.bImag, m),
	}
}

// MulM31Unchecked multiplies by an M31 element without reducing.
func (q *QM31Chip) MulM31Unchecked(x QM31, m M31) QM31 {
	return QM31{
		aReal: q.m31.MulUnchecked(x.aReal, m),
		aImag: q.m31.MulUnchecked(x.aImag, m),
		bReal: q.m31.MulUnchecked(x.bReal, m),
		bImag: q.m31.MulUnchecked(x.bImag, m),
	}
}

// AssertEqual constrains the circuit so that x == y.
func (q *QM31Chip) AssertEqual(x, y QM31) {
	api := q.m31.api
	api.AssertIsEqual(x.aReal.x, y.aReal.x)
	api.AssertIsEqual(x.aImag.x, y.aImag.x)
	api.AssertIsEqual(x.bReal.x, y.bReal.x)
	api.AssertIsEqual(x.bImag.x, y.bImag.x)
}

// ╔══════════════════════════════════╗
// ║          CM31 Arithmetics        ║
// ╚══════════════════════════════════╝

func (q *QM31Chip) cmAddUnchecked(x, y cm31) cm31 {
	return cm31{
		real: q.m31.AddUnchecked(x.real, y.real),
		imag: q.m31.AddUnchecked(x.imag, y.imag),
	}
}

func (q *QM31Chip) cmMulUnchecked(x, y cm31) cm31 {
	ar := q.m31.MulUnchecked(x.real, y.real)
	bi := q.m31.MulUnchecked(x.imag, y.imag)
	r := q.m31.SubUnchecked(ar, bi)

	ai := q.m31.MulUnchecked(x.real, y.imag)
	br := q.m31.MulUnchecked(x.imag, y.real)
	i := q.m31.AddUnchecked(ai, br)

	return cm31{real: r, imag: i}
}

func (q *QM31Chip) cmMulByRUnchecked(x cm31) cm31 {
	twoReal := q.m31.AddUnchecked(x.real, x.real)
	twoImag := q.m31.AddUnchecked(x.imag, x.imag)

	real := q.m31.SubUnchecked(twoReal, x.imag)
	imag := q.m31.AddUnchecked(twoImag, x.real)
	return cm31{real: real, imag: imag}
}

// ╔══════════════════════════════════╗
// ║          QM31 Inversion          ║
// ╚══════════════════════════════════╝

// Inverse computes 1/x.
func (q *QM31Chip) Inverse(x QM31) QM31 {
	api := q.m31.api
	hintInputs := []frontend.Variable{x.aReal.x, x.aImag.x, x.bReal.x, x.bImag.x}
	hintOutputs, err := api.Compiler().NewHint(QM31InverseHint, 4, hintInputs...)
	if err != nil {
		panic(err)
	}

	inv := QM31{
		aReal: NewM31Unchecked(hintOutputs[0]),
		aImag: NewM31Unchecked(hintOutputs[1]),
		bReal: NewM31Unchecked(hintOutputs[2]),
		bImag: NewM31Unchecked(hintOutputs[3]),
	}

	q.m31.RangeCheck(inv.aReal)
	q.m31.RangeCheck(inv.aImag)
	q.m31.RangeCheck(inv.bReal)
	q.m31.RangeCheck(inv.bImag)

	isZero := api.IsZero(x.aReal.x)
	isZero = api.Mul(isZero, api.IsZero(x.aImag.x))
	isZero = api.Mul(isZero, api.IsZero(x.bReal.x))
	isZero = api.Mul(isZero, api.IsZero(x.bImag.x))
	hasInv := api.Sub(1, isZero)

	product := q.Mul(x, inv)
	one := q.One()

	api.AssertIsEqual(api.Select(hasInv, product.aReal.x, one.aReal.x), one.aReal.x)
	api.AssertIsEqual(api.Select(hasInv, product.aImag.x, one.aImag.x), one.aImag.x)
	api.AssertIsEqual(api.Select(hasInv, product.bReal.x, one.bReal.x), one.bReal.x)
	api.AssertIsEqual(api.Select(hasInv, product.bImag.x, one.bImag.x), one.bImag.x)

	return inv
}

// BatchInverse returns component-wise inverses for all values.
func (q *QM31Chip) BatchInverse(values []QM31) []QM31 {
	n := len(values)
	if n == 0 {
		return nil
	}

	prefix := make([]QM31, n)
	prefix[0] = values[0]
	for i := 1; i < n; i++ {
		prefix[i] = q.Mul(prefix[i-1], values[i])
	}

	totalInv := q.Inverse(prefix[n-1])
	inverses := make([]QM31, n)
	inverses[n-1] = totalInv

	curr := totalInv
	for i := n - 1; i >= 1; i-- {
		inverses[i] = q.Mul(prefix[i-1], curr)
		curr = q.Mul(curr, values[i])
	}
	inverses[0] = curr
	return inverses
}

// ╔══════════════════════════════════╗
// ║              Combines            ║
// ╚══════════════════════════════════╝

type InteractionElements struct {
	z           QM31
	alphaPowers []M31
}

func DummyInteractionElements(powerCount int) InteractionElements {
	if powerCount < 0 {
		panic("powerCount must be non-negative")
	}

	alphaPowers := make([]M31, powerCount)
	for i := range alphaPowers {
		alphaPowers[i] = One()
	}

	return InteractionElements{
		z:           QM31{aReal: Zero(), aImag: Zero(), bReal: Zero(), bImag: Zero()},
		alphaPowers: alphaPowers,
	}
}

func (q *QM31Chip) Combine(interactionElements InteractionElements, x []QM31) (QM31, error) {
	sum := interactionElements.z
	for i, alphaPower := range interactionElements.alphaPowers {
		if i >= len(x) {
			return QM31{}, errors.New("not enough alpha powers to combine")
		}
		sum = q.Add(sum, q.MulM31(x[i], alphaPower))
	}
	return sum, nil
}

func QM31InverseHint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	if len(inputs) != 4 {
		panic("QM31InverseHint expects 4 inputs")
	}
	if len(results) != 4 {
		panic("QM31InverseHint expects 4 results")
	}
	vals := [4]uint64{}
	for i, in := range inputs {
		if in.Sign() < 0 || in.Cmp(primeBigInt) >= 0 {
			panic("input not in field")
		}
		vals[i] = in.Uint64()
		if results[i] == nil {
			results[i] = new(big.Int)
		}
		results[i].SetUint64(0)
	}
	if vals[0]|vals[1]|vals[2]|vals[3] == 0 {
		return nil
	}
	mod := uint64(PRIME)
	add := func(a, b uint64) uint64 {
		c := a + b
		if c >= mod {
			c -= mod
		}
		return c
	}
	sub := func(a, b uint64) uint64 {
		if a >= b {
			return a - b
		}
		return mod + a - b
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
	type cm struct{ r, i uint64 }
	cmAdd := func(x, y cm) cm {
		return cm{add(x.r, y.r), add(x.i, y.i)}
	}
	cmSub := func(x, y cm) cm {
		return cm{sub(x.r, y.r), sub(x.i, y.i)}
	}
	cmNeg := func(x cm) cm {
		return cm{neg(x.r), neg(x.i)}
	}
	cmMul := func(x, y cm) cm {
		return cm{
			r: sub(mul(x.r, y.r), mul(x.i, y.i)),
			i: add(mul(x.r, y.i), mul(x.i, y.r)),
		}
	}
	cmSquare := func(x cm) cm {
		return cmMul(x, x)
	}
	cmInv := func(x cm) cm {
		if x.r == 0 && x.i == 0 {
			return x
		}
		den := add(mul(x.r, x.r), mul(x.i, x.i))
		inv := pow2147483645M31(den)
		return cm{mul(x.r, inv), mul(neg(x.i), inv)}
	}
	a := cm{vals[0], vals[1]}
	b := cm{vals[2], vals[3]}
	b2 := cmSquare(b)
	ib2 := cm{neg(b2.i), b2.r}
	den := cmSub(cmSquare(a), cmAdd(cmAdd(b2, b2), ib2))
	denInv := cmInv(den)
	aInv := cmMul(a, denInv)
	bInv := cmNeg(cmMul(b, denInv))
	results[0].SetUint64(aInv.r)
	results[1].SetUint64(aInv.i)
	results[2].SetUint64(bInv.r)
	results[3].SetUint64(bInv.i)
	return nil
}
