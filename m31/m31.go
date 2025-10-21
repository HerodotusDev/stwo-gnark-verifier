// The structure for the M31 chip and for its operations was inspired from:
// https://github.com/succinctlabs/gnark-plonky2-verifier/blob/main/goldilocks/base.go
// The M31 operation logic comes from:
// https://github.com/starkware-libs/stwo/blob/dev/crates/stwo/src/core/fields/m31.rs

package m31

import (
	"fmt"
	"math"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
)

const PRIME uint32 = 1<<31 - 1

var primeBigInt = new(big.Int).SetUint64(uint64(PRIME))

func init() {
	solver.RegisterHint(MulAddHint)
	solver.RegisterHint(SplitLimbsHint)
	solver.RegisterHint(InverseHint)
	solver.RegisterHint(ReduceHint)
	solver.RegisterHint(Decompose16Hint)
}

// ╔══════════════════════════════════╗
// ║        M31 Field Element         ║
// ╚══════════════════════════════════╝

// A type alias used to represent M31 field elements.
type M31 struct {
	Limb frontend.Variable
}

// Variable exposes the underlying frontend variable representing the element.
func (m M31) Variable() frontend.Variable {
	return m.Limb
}

// Creates a new M31 field element from an existing variable. Assumes that the element is
// already reduced.
func NewM31Unchecked(x frontend.Variable) M31 {
	return M31{Limb: x}
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
	rangeChecker frontend.Rangechecker
}

// Creates a new M31 chip
func NewM31Chip(api frontend.API) *M31Chip {
	return &M31Chip{api: api, rangeChecker: rangecheck.New(api)}
}

// ╔══════════════════════════════════╗
// ║          M31 Arithemtics         ║
// ╚══════════════════════════════════╝

// Adds two M31 field elements without reducing the result.
func (p *M31Chip) AddUnchecked(a M31, b M31) M31 {
	return NewM31Unchecked(p.api.Add(a.Limb, b.Limb))
}

// Adds two M31 field elements and returns a value within the M31 field.
func (p *M31Chip) Add(a M31, b M31) M31 {
	return p.MulAdd(a, One(), b)
}

// Subracts two M31 field elements without reducing the result.
func (p *M31Chip) SubUnchecked(a M31, b M31) M31 {
	return NewM31Unchecked(p.api.Add(a.Limb, p.api.Mul(b.Limb, NegOne().Limb)))
}

// Subracts two M31 field elements and returns a value within the M31 field.
func (p *M31Chip) Sub(a M31, b M31) M31 {
	return p.MulAdd(b, NegOne(), a)
}

// Negates an M31 field element.
func (p *M31Chip) Neg(a M31) M31 {
	return p.Mul(a, NegOne())
}

// Multiplies two M31 field elements without reducing the result.
func (p *M31Chip) MulUnchecked(a M31, b M31) M31 {
	return NewM31Unchecked(p.api.Mul(a.Limb, b.Limb))
}

// Multiplies two M31 field elements and returns a value within the M31 field.
func (p *M31Chip) Mul(a M31, b M31) M31 {
	return p.MulAdd(a, b, Zero())
}

// Performs a * b + c and returns a value without reducing the result.
func (p *M31Chip) MulAddUnchecked(a M31, b M31, c M31) M31 {
	cLimbCopy := p.api.Mul(c.Limb, 1)
	return NewM31Unchecked(p.api.MulAcc(cLimbCopy, a.Limb, b.Limb))
}

// Performs a * b + c and returns a value within the M31 field.
func (p *M31Chip) MulAdd(a M31, b M31, c M31) M31 {
	result, err := p.api.Compiler().NewHint(MulAddHint, 2, a.Limb, b.Limb, c.Limb)
	if err != nil {
		panic(err)
	}

	quotient := NewM31Unchecked(result[0])
	remainder := NewM31Unchecked(result[1])

	cLimbCopy := p.api.Mul(c.Limb, 1)
	lhs := p.api.MulAcc(cLimbCopy, a.Limb, b.Limb)
	rhs := p.api.MulAcc(remainder.Limb, PRIME, quotient.Limb)
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

// ╔══════════════════════════════════╗
// ║          M31 Inversion           ║
// ╚══════════════════════════════════╝

// BatchInverse returns the component-wise inverse of the provided values.
// All inputs must be non-zero; otherwise the circuit will be unsatisfied.
func (p *M31Chip) BatchInverse(values []M31) []M31 {
	n := len(values)
	if n == 0 {
		return nil
	}

	prefix := make([]M31, n)
	prefix[0] = values[0]
	for i := 1; i < n; i++ {
		prefix[i] = p.Mul(prefix[i-1], values[i])
	}

	totalInverse, hasInv := p.Inverse(prefix[n-1])
	p.api.AssertIsEqual(hasInv, frontend.Variable(1))

	inverses := make([]M31, n)
	inverses[n-1] = totalInverse

	curr := totalInverse
	for i := n - 1; i >= 1; i-- {
		inverses[i] = p.Mul(prefix[i-1], curr)
		curr = p.Mul(curr, values[i])
	}
	inverses[0] = curr

	return inverses
}

// Computes the inverse of a field element x such that x * x^-1 = 1.
func (p *M31Chip) Inverse(x M31) (M31, frontend.Variable) {
	result, err := p.api.Compiler().NewHint(InverseHint, 1, x.Limb)
	if err != nil {
		panic(err)
	}

	inverse := NewM31Unchecked(result[0])
	hasInv := p.api.Sub(1, p.api.IsZero(x.Limb))
	p.RangeCheck(inverse)

	product := p.Mul(inverse, x)
	productToCheck := p.api.Select(hasInv, product.Limb, frontend.Variable(1))
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
// ║          M31 Range Check         ║
// ╚══════════════════════════════════╝

// RangeCheck checks that an M31 element is within the field.
func (p *M31Chip) RangeCheck(x M31) {
	result, err := p.api.Compiler().NewHint(SplitLimbsHint, 2, x.Limb)
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
		x.Limb,
	)

	p.rangeChecker.Check(lo, 16)
	p.rangeChecker.Check(p.api.Mul(hi, 2), 16)
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

// ╔══════════════════════════════════╗
// ║          M31 Reduction           ║
// ╚══════════════════════════════════╝

// Returns val % PRIME when val is in the range [0, 2*PRIME)
// Use to reduce the result of an addition
func (p *M31Chip) PartialReduce(x M31) M31 {
	return p.ReduceWithMaxBits(x, quotientBitsPerAdd)
}

// Returns val % PRIME when val is in the range [0, PRIME^2)
// Use to reduce the result of a multiplication
func (p *M31Chip) FullReduce(x M31) M31 {
	return p.ReduceWithMaxBits(x, 32)
}

// reduceWithMaxBits reduces x modulo the field using a quotient bounded by maxNbBits.
func (p *M31Chip) ReduceWithMaxBits(x M31, maxNbBits uint64) M31 {
	result, err := p.api.Compiler().NewHint(ReduceHint, 2, x.Limb)
	if err != nil {
		panic(err)
	}

	quotient := result[0]
	remainder := NewM31Unchecked(result[1])

	p.RangeCheck(remainder)

	if maxNbBits == 0 {
		p.api.AssertIsEqual(quotient, frontend.Variable(0))
	} else {
		aligned := nextMultipleOf16(maxNbBits)
		nbLimbs := int(aligned / 16)

		limbs, err := p.api.Compiler().NewHint(
			Decompose16Hint,
			nbLimbs,
			quotient,
			frontend.Variable(nbLimbs),
		)
		if err != nil {
			panic(err)
		}

		reconstructed := frontend.Variable(0)
		base := frontend.Variable(uint64(1 << 16))
		factor := frontend.Variable(1)
		for _, limb := range limbs {
			// Note that the even though the last limb of quotient might be less than 16 bits,
			// 16-range checking it is sufficient as the quotient MAX_QUOTIENT_BITS is a safe bound.
			p.rangeChecker.Check(limb, 16)
			reconstructed = p.api.Add(reconstructed, p.api.Mul(limb, factor))
			factor = p.api.Mul(factor, base)
		}
		p.api.AssertIsEqual(reconstructed, quotient)
	}

	p.api.AssertIsEqual(
		x.Limb,
		p.api.Add(
			p.api.Mul(quotient, PRIME),
			remainder.Limb,
		),
	)

	return remainder
}

// ReduceHint witnesses quotient and remainder when reducing a value modulo the field.
func ReduceHint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	if len(inputs) != 1 {
		return fmt.Errorf("ReduceHint expects 1 input operand")
	}
	if len(results) != 2 {
		return fmt.Errorf("ReduceHint expects 2 result operands")
	}

	val := new(big.Int).Set(inputs[0])
	quotient := new(big.Int)
	remainder := new(big.Int)
	quotient.QuoRem(val, primeBigInt, remainder)

	results[0] = quotient
	results[1] = remainder
	return nil
}

// Decompose16Hint decomposes a value into 16-bit limbs for range checking.
func Decompose16Hint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	if len(inputs) != 2 {
		return fmt.Errorf("Decompose16Hint expects value and limb count")
	}

	nbLimbs := int(inputs[1].Int64())
	if nbLimbs < 0 {
		return fmt.Errorf("invalid limb count")
	}
	if len(results) != nbLimbs {
		return fmt.Errorf("expected %d result limbs", nbLimbs)
	}

	val := new(big.Int).Set(inputs[0])
	base := new(big.Int).Lsh(big.NewInt(1), 16)

	for i := 0; i < nbLimbs; i++ {
		quotient := new(big.Int)
		remainder := new(big.Int)
		quotient.QuoRem(val, base, remainder)
		results[i] = remainder
		val = quotient
	}

	if val.Sign() != 0 {
		return fmt.Errorf("value exceeds allocated limbs")
	}

	return nil
}

// ╔══════════════════════════════════╗
// ║        M31 Smart Accumulator     ║
// ╚══════════════════════════════════╝

const (
	quotientBitsPerAdd = 1                      // adding an element can increase the quotient by at most 1 bit
	maxQuotientBits    = ((254 - 31) / 16) * 16 // fit in BN254 and align on 16-bit limbs
)

func validateBudget(bits uint64) uint64 {
	if bits > maxQuotientBits {
		panic("smart accumulator budget exceeds allowed range; reduce the expression before enqueuing it")
	}
	return bits
}

// SmartAccumulator batches expressions while deferring reductions.
// Callers must provide a bit budget for each expression they enqueue.
type SmartAccumulator struct {
	chip     *M31Chip
	sum      M31
	usedBits uint64
}

// NewSmartAccumulator creates a new smart accumulator anchored on this chip.
func (p *M31Chip) NewSmartAccumulator() *SmartAccumulator {
	return &SmartAccumulator{
		chip:     p,
		sum:      Zero(),
		usedBits: 0,
	}
}

// AddExpression enqueues an unreduced expression together with its bit budget
func (acc *SmartAccumulator) AddExpression(expr M31, exprBudget uint64) {
	exprBudget = validateBudget(exprBudget + quotientBitsPerAdd)

	// Flush if the addition creates an overflow and update the used bits
	if acc.usedBits != 0 {
		potential := max(acc.usedBits, exprBudget) + quotientBitsPerAdd
		if potential > maxQuotientBits {
			acc.flush()
		} else {
			exprBudget = potential
		}
	}
	acc.usedBits = exprBudget

	// Perform the addition
	acc.sum = acc.chip.AddUnchecked(acc.sum, expr)

	if acc.usedBits == maxQuotientBits {
		acc.flush()
	}
}

// MulExpression multiplies the running sum by an expression whose bit budget is provided.
func (acc *SmartAccumulator) MulExpression(expr M31, exprBudget uint64) {
	exprBudget = validateBudget(exprBudget)

	// Flush if the multiplication creates an overflow
	if acc.usedBits != 0 && acc.usedBits+exprBudget > maxQuotientBits {
		acc.flush()
	}

	// Perform the multiplication
	acc.sum = acc.chip.MulUnchecked(acc.sum, expr)

	// Update the used bits
	if acc.usedBits == 0 {
		acc.usedBits = exprBudget
	} else {
		acc.usedBits = acc.usedBits + exprBudget
	}

	if acc.usedBits == maxQuotientBits {
		acc.flush()
	}
}

// Finalize reduces the pending sum (if any) and returns the canonical field element.
func (acc *SmartAccumulator) Finalize() M31 {
	acc.flush()
	return acc.sum
}

func (acc *SmartAccumulator) flush() {
	if acc.usedBits == 0 {
		return
	}
	aligned := nextMultipleOf16(acc.usedBits)
	acc.sum = acc.chip.ReduceWithMaxBits(acc.sum, aligned)
	acc.usedBits = 0
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

// Returns the next multiple of 16 greater than or equal to bits.
func nextMultipleOf16(bits uint64) uint64 {
	if bits == 0 {
		return 0
	}
	return ((bits + 15) / 16) * 16
}
