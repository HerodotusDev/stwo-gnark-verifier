package m31

import (
	"fmt"
	"math"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
)

const PRIME uint32 = 1<<31 - 1

var primeBigInt = new(big.Int).SetUint64(uint64(PRIME))

func init() {
	solver.RegisterHint(MulAddHint)
	solver.RegisterHint(SplitLimbsHint)
	solver.RegisterHint(InverseHint)
}

// ╔══════════════════════════════════╗
// ║        M31 Field Element         ║
// ╚══════════════════════════════════╝

// A type alias used to represent M31 field elements.
type M31 struct {
	x frontend.Variable
}

// Creates a new M31 field element from an existing variable. Assumes that the element is
// already reduced.
func NewM31Unchecked(x frontend.Variable) M31 {
	return M31{x}
}

// The zero element in the M31 field.
func Zero() M31 {
	return NewM31Unchecked(0)
}

// The one element in the M31 field.
func One() M31 {
	return NewM31Unchecked(1)
}

// The negative one element in the M31 field.
func NegOne() M31 {
	return NewM31Unchecked(PRIME - 1)
}

// ╔══════════════════════════════════╗
// ║        	 M31 Chip             ║
// ╚══════════════════════════════════╝

// A chip for M31 field operations
type M31Chip struct {
	api          frontend.API
	rangeChecker RC16Chip
}

// Creates a new M31 chip
func NewM31Chip(api frontend.API) *M31Chip {
	return &M31Chip{api: api, rangeChecker: *NewRC16Chip(api)}
}

// ╔══════════════════════════════════╗
// ║       M31 Basic Operations       ║
// ╚══════════════════════════════════╝

// Adds two M31 field elements without reducing the result.
func (p *M31Chip) AddUnchecked(a M31, b M31) M31 {
	return NewM31Unchecked(p.api.Add(a.x, b.x))
}

// Adds two M31 field elements and returns a value within the M31 field.
func (p *M31Chip) Add(a M31, b M31) M31 {
	return p.MulAdd(a, One(), b)
}

// Subracts two M31 field elements without reducing the result.
func (p *M31Chip) SubUnchecked(a M31, b M31) M31 {
	return NewM31Unchecked(p.api.Add(a.x, p.api.Mul(b.x, NegOne().x)))
}

// Subracts two M31 field elements and returns a value within the M31 field.
func (p *M31Chip) Sub(a M31, b M31) M31 {
	return p.MulAdd(b, NegOne(), a)
}

// Multiplies two M31 field elements without reducing the result.
func (p *M31Chip) MulUnchecked(a M31, b M31) M31 {
	return NewM31Unchecked(p.api.Mul(a.x, b.x))
}

// Multiplies two M31 field elements and returns a value within the M31 field.
func (p *M31Chip) Mul(a M31, b M31) M31 {
	return p.MulAdd(a, b, Zero())
}

// Performs a * b + c and returns a value without reducing the result.
func (p *M31Chip) MulAddUnchecked(a M31, b M31, c M31) M31 {
	cLimbCopy := p.api.Mul(c.x, 1)
	return NewM31Unchecked(p.api.MulAcc(cLimbCopy, a.x, b.x))
}

// Performs a * b + c and returns a value within the M31 field.
func (p *M31Chip) MulAdd(a M31, b M31, c M31) M31 {
	result, err := p.api.Compiler().NewHint(MulAddHint, 2, a.x, b.x, c.x)
	if err != nil {
		panic(err)
	}

	quotient := NewM31Unchecked(result[0])
	remainder := NewM31Unchecked(result[1])

	cLimbCopy := p.api.Mul(c.x, 1)
	lhs := p.api.MulAcc(cLimbCopy, a.x, b.x)
	rhs := p.api.MulAcc(remainder.x, PRIME, quotient.x)
	p.api.AssertIsEqual(lhs, rhs)

	p.RangeCheck(quotient)
	p.RangeCheck(remainder)
	return remainder
}

// The hint used to compute MulAdd.
func MulAddHint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	if len(inputs) != 3 {
		panic("MulAddHint expects 3 input operands")
	}

	if len(results) != 2 {
		panic("MulAddHint expects 2 result operands")
	}

	for _, operand := range inputs {
		if operand.Sign() < 0 || operand.Cmp(primeBigInt) >= 0 {
			panic(fmt.Sprintf("%s is not in the field", operand.String()))
		}
	}

	a := inputs[0].Uint64()
	b := inputs[1].Uint64()
	c := inputs[2].Uint64()

	product := a * b
	if product > math.MaxUint64-c {
		panic("MulAddHint overflow")
	}
	sum := product + c

	primeUint := uint64(PRIME)
	quotient := sum / primeUint
	remainder := sum % primeUint

	if results[0] == nil {
		results[0] = new(big.Int)
	}
	if results[1] == nil {
		results[1] = new(big.Int)
	}

	results[0].SetUint64(quotient)
	results[1].SetUint64(remainder)

	return nil
}

func (p *M31Chip) RangeCheck(x M31) {
	result, err := p.api.Compiler().NewHint(SplitLimbsHint, 2, x.x)
	if err != nil {
		panic(err)
	}

	// We check that this is a valid decomposition of the M31's element and range-check each limb.
	lo := result[0]
	hi := result[1]
	p.api.AssertIsEqual(
		p.api.Add(
			p.api.Mul(hi, uint32(1<<16)),
			lo,
		),
		x.x,
	)

	p.rangeChecker.Check16(lo)
	p.rangeChecker.Check16(p.api.Mul(hi, 2))
}

// The hint used to split an M31 element into 2 16-bit limbs.
func SplitLimbsHint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	if len(inputs) != 1 {
		panic("SplitLimbsHint expects 1 input operand")
	}

	if len(results) != 2 {
		panic("SplitLimbsHint expects 2 result operands")
	}

	input := inputs[0]

	if input.Sign() < 0 || input.Cmp(primeBigInt) >= 0 {
		return fmt.Errorf("input is not in the field")
	}

	value := input.Uint64()
	const limbMask = (1 << 16) - 1

	// The least significant bits
	results[0].SetUint64(value & limbMask)
	// The most significant bits
	results[1].SetUint64(value >> 16)

	return nil
}

// Computes the inverse of a field element x such that x * x^-1 = 1.
func (p *M31Chip) Inverse(x M31) (M31, frontend.Variable) {
	result, err := p.api.Compiler().NewHint(InverseHint, 1, x.x)
	if err != nil {
		panic(err)
	}

	inverse := NewM31Unchecked(result[0])
	hasInv := p.api.Sub(1, p.api.IsZero(x.x))
	p.RangeCheck(inverse)

	product := p.Mul(inverse, x)
	productToCheck := p.api.Select(hasInv, product.x, frontend.Variable(1))
	p.api.AssertIsEqual(productToCheck, frontend.Variable(1))

	return inverse, hasInv
}

// The hint used to compute Inverse.
func InverseHint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	if len(inputs) != 1 {
		panic("InverseHint expects 1 input operand")
	}

	input := inputs[0]
	if input.Cmp(primeBigInt) >= 0 || input.Sign() < 0 {
		return fmt.Errorf("input is not in the field")
	}

	value := input.Uint64()
	var inverse uint64
	if value != 0 {
		inverse = pow2147483645M31(value)
	}

	if len(results) != 1 {
		panic("InverseHint expects exactly 1 result operand")
	}

	if results[0] == nil {
		results[0] = new(big.Int)
	}
	results[0].SetUint64(inverse)

	return nil
}

// ╔══════════════════════════════════╗
// ║       M31 Helper functions       ║
// ╚══════════════════════════════════╝

func pow2147483645M31(v uint64) uint64 {
	t0 := mulModM31(squareNM31(v, 2), v)
	t1 := mulModM31(squareNM31(t0, 1), t0)
	t2 := mulModM31(squareNM31(t1, 3), t0)
	t3 := mulModM31(squareNM31(t2, 1), t0)
	t4 := mulModM31(squareNM31(t3, 8), t3)
	t5 := mulModM31(squareNM31(t4, 8), t3)
	return mulModM31(squareNM31(t5, 7), t2)
}

func squareNM31(x uint64, n int) uint64 {
	for i := 0; i < n; i++ {
		x = mulModM31(x, x)
	}
	return x
}

func mulModM31(a, b uint64) uint64 {
	return (a * b) % uint64(PRIME)
}
