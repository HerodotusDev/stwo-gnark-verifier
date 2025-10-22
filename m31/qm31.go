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
	AReal M31
	AImag M31
	BReal M31
	BImag M31
}

type cm31 struct {
	Real M31
	Imag M31
}

var (
	coord1 = QM31{
		AReal: Zero(),
		AImag: One(),
		BReal: Zero(),
		BImag: Zero(),
	}
	coord2 = QM31{
		AReal: Zero(),
		AImag: Zero(),
		BReal: One(),
		BImag: Zero(),
	}
	coord3 = QM31{
		AReal: Zero(),
		AImag: Zero(),
		BReal: Zero(),
		BImag: One(),
	}
)

func NewQM31(aReal, aImag, bReal, bImag uint64) QM31 {
	return QM31{
		AReal: NewM31Unchecked(aReal),
		AImag: NewM31Unchecked(aImag),
		BReal: NewM31Unchecked(bReal),
		BImag: NewM31Unchecked(bImag),
	}
}

func NewQM31FromArrays(a [][]uint64) QM31 {
	return NewQM31(a[0][0], a[0][1], a[1][0], a[1][1])
}

// Components returns the four M31 coordinates of the extension element.
func (q QM31) Components() [4]M31 {
	return [4]M31{q.AReal, q.AImag, q.BReal, q.BImag}
}

// NewQM31FromComponents builds a QM31 element from its four M31 coordinates.
func NewQM31FromComponents(aReal, aImag, bReal, bImag M31) QM31 {
	return QM31{
		AReal: aReal,
		AImag: aImag,
		BReal: bReal,
		BImag: bImag,
	}
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
		AReal: m,
		AImag: Zero(),
		BReal: Zero(),
		BImag: Zero(),
	}
}

func (q *QM31Chip) FromPartialEvals(q0, q1, q2, q3 QM31) QM31 {
	f1 := q.Mul(q1, coord1)
	f2 := q.Mul(q2, coord2)
	f3 := q.Mul(q3, coord3)
	return q.Add(q.Add(q.Add(q0, f1), f2), f3)
}

// Zero returns the additive identity.
func (q *QM31Chip) Zero() QM31 {
	return QM31{
		AReal: Zero(),
		AImag: Zero(),
		BReal: Zero(),
		BImag: Zero(),
	}
}

// One returns the multiplicative identity.
func (q *QM31Chip) One() QM31 {
	return QM31{
		AReal: One(),
		AImag: Zero(),
		BReal: Zero(),
		BImag: Zero(),
	}
}

func (q *QM31Chip) Println(x QM31) {
	q.m31.api.Println("aReal", x.AReal.Limb)
	q.m31.api.Println("aImag", x.AImag.Limb)
	q.m31.api.Println("bReal", x.BReal.Limb)
	q.m31.api.Println("bImag", x.BImag.Limb)
}

// ╔══════════════════════════════════╗
// ║          QM31 Arithmetics        ║
// ╚══════════════════════════════════╝

// Add computes x + y.
func (q *QM31Chip) Add(x, y QM31) QM31 {
	return QM31{
		AReal: q.m31.Add(x.AReal, y.AReal),
		AImag: q.m31.Add(x.AImag, y.AImag),
		BReal: q.m31.Add(x.BReal, y.BReal),
		BImag: q.m31.Add(x.BImag, y.BImag),
	}
}

// AddUnchecked computes x + y without reducing the result.
func (q *QM31Chip) AddUnchecked(x, y QM31) QM31 {
	return QM31{
		AReal: q.m31.AddUnchecked(x.AReal, y.AReal),
		AImag: q.m31.AddUnchecked(x.AImag, y.AImag),
		BReal: q.m31.AddUnchecked(x.BReal, y.BReal),
		BImag: q.m31.AddUnchecked(x.BImag, y.BImag),
	}
}

// Sub computes x - y.
func (q *QM31Chip) Sub(x, y QM31) QM31 {
	return QM31{
		AReal: q.m31.Sub(x.AReal, y.AReal),
		AImag: q.m31.Sub(x.AImag, y.AImag),
		BReal: q.m31.Sub(x.BReal, y.BReal),
		BImag: q.m31.Sub(x.BImag, y.BImag),
	}
}

// SubUnchecked computes x - y without reducing.
func (q *QM31Chip) SubUnchecked(x, y QM31) QM31 {
	return QM31{
		AReal: q.m31.SubUnchecked(x.AReal, y.AReal),
		AImag: q.m31.SubUnchecked(x.AImag, y.AImag),
		BReal: q.m31.SubUnchecked(x.BReal, y.BReal),
		BImag: q.m31.SubUnchecked(x.BImag, y.BImag),
	}
}

// Neg returns -x.
func (q *QM31Chip) Neg(x QM31) QM31 {
	return QM31{
		AReal: q.m31.Neg(x.AReal),
		AImag: q.m31.Neg(x.AImag),
		BReal: q.m31.Neg(x.BReal),
		BImag: q.m31.Neg(x.BImag),
	}
}

// Mul computes (a + u b)(c + u d) with u^2 = 2 + i.
func (q *QM31Chip) Mul(lhs, rhs QM31) QM31 {
	resultUnreduced := q.MulUnchecked(lhs, rhs)
	// cmMulUnchecked yields a CM31 with coefficients of at most 97 bits.
	// rbd has coefficients of at most 161 bits (cm mul of 97 bit coefficients and 31 bit coefficients).
	// A and B are thus of at most 162 bits (carry bit).
	// 16 * ceil((162-31)/16) = 144 bits.
	return QM31{
		AReal: q.m31.ReduceWithMaxBits(resultUnreduced.AReal, 144),
		AImag: q.m31.ReduceWithMaxBits(resultUnreduced.AImag, 144),
		BReal: q.m31.ReduceWithMaxBits(resultUnreduced.BReal, 144),
		BImag: q.m31.ReduceWithMaxBits(resultUnreduced.BImag, 144),
	}
}

// MulUnchecked multiplies without reducing intermediate terms.
func (q *QM31Chip) MulUnchecked(lhs, rhs QM31) QM31 {
	a := cm31{lhs.AReal, lhs.AImag}
	b := cm31{lhs.BReal, lhs.BImag}
	c := cm31{rhs.AReal, rhs.AImag}
	d := cm31{rhs.BReal, rhs.BImag}

	ac := q.cmMulUnchecked(a, c)
	bd := q.cmMulUnchecked(b, d)
	rbd := q.cmMulByRUnchecked(bd)
	ad := q.cmMulUnchecked(a, d)
	bc := q.cmMulUnchecked(b, c)

	A := q.cmAddUnchecked(ac, rbd)
	B := q.cmAddUnchecked(ad, bc)

	return QM31{
		AReal: A.Real,
		AImag: A.Imag,
		BReal: B.Real,
		BImag: B.Imag,
	}
}

// MulM31 multiplies by a base M31 element.
func (q *QM31Chip) MulM31(x QM31, m M31) QM31 {
	return QM31{
		AReal: q.m31.Mul(x.AReal, m),
		AImag: q.m31.Mul(x.AImag, m),
		BReal: q.m31.Mul(x.BReal, m),
		BImag: q.m31.Mul(x.BImag, m),
	}
}

// MulM31Unchecked multiplies by an M31 element without reducing.
func (q *QM31Chip) MulM31Unchecked(x QM31, m M31) QM31 {
	return QM31{
		AReal: q.m31.MulUnchecked(x.AReal, m),
		AImag: q.m31.MulUnchecked(x.AImag, m),
		BReal: q.m31.MulUnchecked(x.BReal, m),
		BImag: q.m31.MulUnchecked(x.BImag, m),
	}
}

// AssertEqual constrains the circuit so that x == y.
func (q *QM31Chip) AssertEqual(x, y QM31) {
	api := q.m31.api
	api.AssertIsEqual(x.AReal.Limb, y.AReal.Limb)
	api.AssertIsEqual(x.AImag.Limb, y.AImag.Limb)
	api.AssertIsEqual(x.BReal.Limb, y.BReal.Limb)
	api.AssertIsEqual(x.BImag.Limb, y.BImag.Limb)
}

// ╔══════════════════════════════════╗
// ║          CM31 Arithmetics        ║
// ╚══════════════════════════════════╝

func (q *QM31Chip) cmAddUnchecked(x, y cm31) cm31 {
	return cm31{
		Real: q.m31.AddUnchecked(x.Real, y.Real),
		Imag: q.m31.AddUnchecked(x.Imag, y.Imag),
	}
}

func (q *QM31Chip) cmMulUnchecked(x, y cm31) cm31 {
	ar := q.m31.MulUnchecked(x.Real, y.Real)
	bi := q.m31.MulUnchecked(x.Imag, y.Imag)
	r := q.m31.SubUnchecked(ar, bi)

	ai := q.m31.MulUnchecked(x.Real, y.Imag)
	br := q.m31.MulUnchecked(x.Imag, y.Real)
	i := q.m31.AddUnchecked(ai, br)

	return cm31{Real: r, Imag: i}
}

func (q *QM31Chip) cmMulByRUnchecked(x cm31) cm31 {
	twoReal := q.m31.AddUnchecked(x.Real, x.Real)
	twoImag := q.m31.AddUnchecked(x.Imag, x.Imag)

	real := q.m31.SubUnchecked(twoReal, x.Imag)
	imag := q.m31.AddUnchecked(twoImag, x.Real)
	return cm31{Real: real, Imag: imag}
}

// ╔══════════════════════════════════╗
// ║          QM31 Inversion          ║
// ╚══════════════════════════════════╝

// Inverse computes 1/x.
func (q *QM31Chip) Inverse(x QM31) QM31 {
	api := q.m31.api
	hintInputs := []frontend.Variable{x.AReal.Limb, x.AImag.Limb, x.BReal.Limb, x.BImag.Limb}
	hintOutputs, err := api.Compiler().NewHint(QM31InverseHint, 4, hintInputs...)
	if err != nil {
		panic(err)
	}

	inv := QM31{
		AReal: NewM31Unchecked(hintOutputs[0]),
		AImag: NewM31Unchecked(hintOutputs[1]),
		BReal: NewM31Unchecked(hintOutputs[2]),
		BImag: NewM31Unchecked(hintOutputs[3]),
	}

	q.m31.RangeCheck(inv.AReal)
	q.m31.RangeCheck(inv.AImag)
	q.m31.RangeCheck(inv.BReal)
	q.m31.RangeCheck(inv.BImag)

	isZero := api.IsZero(x.AReal.Limb)
	isZero = api.Mul(isZero, api.IsZero(x.AImag.Limb))
	isZero = api.Mul(isZero, api.IsZero(x.BReal.Limb))
	isZero = api.Mul(isZero, api.IsZero(x.BImag.Limb))
	hasInv := api.Sub(1, isZero)

	product := q.Mul(x, inv)
	one := q.One()

	api.AssertIsEqual(api.Select(hasInv, product.AReal.Limb, one.AReal.Limb), one.AReal.Limb)
	api.AssertIsEqual(api.Select(hasInv, product.AImag.Limb, one.AImag.Limb), one.AImag.Limb)
	api.AssertIsEqual(api.Select(hasInv, product.BReal.Limb, one.BReal.Limb), one.BReal.Limb)
	api.AssertIsEqual(api.Select(hasInv, product.BImag.Limb, one.BImag.Limb), one.BImag.Limb)

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
		z:           QM31{AReal: One(), AImag: Zero(), BReal: Zero(), BImag: Zero()},
		alphaPowers: alphaPowers,
	}
}

func (q *QM31Chip) Combine(interactionElements InteractionElements, x []QM31) (QM31, error) {
	sum := q.Neg(interactionElements.z)
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
