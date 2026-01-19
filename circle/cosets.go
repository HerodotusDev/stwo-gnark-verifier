package circle

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/HerodotusDev/stwo-gnark-verifier/utils"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/conversion"
	"github.com/consensys/gnark/std/math/uints"
)

// ╔══════════════════════════════════╗
// ║              Coset               ║
// ╚══════════════════════════════════╝

// Coset represents initial + <step>.
// Since column sizes are known at circuit compile time, logSize is a uint32
type Coset struct {
	circleChip *CircleChip

	initial CirclePointIndex
	step    CirclePointIndex
	logSize frontend.Variable
}

// NewCoset builds a coset whose step size is the subgroup generator of logSize.
func NewCoset(circleChip *CircleChip, initial CirclePointIndex, logSize frontend.Variable) Coset {
	stepSize := SubgroupGenerator(circleChip, logSize)
	return Coset{
		circleChip: circleChip,
		initial:    initial,
		step:       stepSize,
		logSize:    logSize,
	}
}

// halfOdds returns the odds half of the coset.
func (c Coset) halfOdds(logSize frontend.Variable) Coset {
	return NewCoset(c.circleChip, SubgroupGenerator(c.circleChip, c.circleChip.api.Add(logSize, frontend.Variable(2))), logSize)
}

// Double returns the double of the coset.
// Coset {initial, step, logSize} -> Coset {initial, step * 2, logSize - 1}
func (c Coset) Double() Coset {
	return NewCoset(c.circleChip, c.initial.Mul(uints.NewU32(2)), c.circleChip.api.Sub(c.logSize, frontend.Variable(1)))
}

// IndexAt returns the circle point index at the given index.
func (c Coset) IndexAt(i uints.U32) CirclePointIndex {
	return c.circleChip.AddPointIndex(c.initial, c.step.Mul(i))
}

// LogSize returns the coset log size.
func (c Coset) LogSize() frontend.Variable {
	return c.logSize
}

// Size returns the size of the coset.
func (c Coset) Size() frontend.Variable {
	return utils.Pow2(c.circleChip.api, c.logSize, 8)
}

// Step returns the step of the coset.
func (c Coset) Step() CirclePointIndex {
	return c.step
}

// ╔══════════════════════════════════╗
// ║           Canonic Coset          ║
// ╚══════════════════════════════════╝

// CanonicCoset denotes G_{2n} + <G_n>.
type CanonicCoset struct {
	coset Coset
}

// NewCanonicCoset creates a canonic coset of size 2^logSize.
func NewCanonicCoset(circleChip *CircleChip, logSize frontend.Variable) CanonicCoset {
	initial := SubgroupGenerator(circleChip, circleChip.api.Add(logSize, frontend.Variable(1)))
	return CanonicCoset{
		coset: NewCoset(circleChip, initial, logSize),
	}
}

// HalfCoset returns half of coset.
func (c CanonicCoset) HalfCoset() Coset {
	return c.coset.halfOdds(c.coset.circleChip.api.Sub(c.coset.logSize, frontend.Variable(1)))
}

// CircleDomain returns the corresponding circle domain.
func (c CanonicCoset) CircleDomain() CircleDomain {
	return NewCircleDomain(c.HalfCoset())
}

// Coset returns the underlying coset.
func (c CanonicCoset) Coset() Coset {
	return c.coset
}

// LogSize returns the coset log size.
func (c CanonicCoset) LogSize() frontend.Variable {
	return c.coset.logSize
}

// ╔══════════════════════════════════╗
// ║           Circle Domain          ║
// ╚══════════════════════════════════╝

// CircleDomain represents a CircleDomain
type CircleDomain struct {
	halfCoset Coset
}

// NewCircleDomain creates a new circle domain.
func NewCircleDomain(halfCoset Coset) CircleDomain {
	return CircleDomain{
		halfCoset: halfCoset,
	}
}

// LogSize returns the log size of the circle domain.
func (d CircleDomain) LogSize() frontend.Variable {
	return d.halfCoset.circleChip.api.Add(d.halfCoset.logSize, frontend.Variable(1))
}

// At returns the base point at the given index.
func (d CircleDomain) At(i uints.U32) BasePoint {
	return d.IndexAt(i).Point()
}

// IndexAt returns the circle point index at the given index.
func (d CircleDomain) IndexAt(i uints.U32) CirclePointIndex {
	sizeNative := frontend.Variable(d.halfCoset.Size())
	iNative, err := conversion.BytesToNative(d.halfCoset.circleChip.api, i[:])
	if err != nil {
		panic(err)
	}
	isLess := d.halfCoset.circleChip.comparator.IsLess(iNative, sizeNative)

	// compute i - d.halfCoset.Size()
	iMinSizeNative := d.halfCoset.circleChip.api.Sub(iNative, sizeNative)
	iMinSizeBytes, err := conversion.NativeToBytes(d.halfCoset.circleChip.api, iMinSizeNative)
	if err != nil {
		panic(err)
	}
	iMinSize := uints.U32{iMinSizeBytes[len(iMinSizeBytes)-1], iMinSizeBytes[len(iMinSizeBytes)-2], iMinSizeBytes[len(iMinSizeBytes)-3], iMinSizeBytes[len(iMinSizeBytes)-4]}
	iBe := uints.U32{i[3], i[2], i[1], i[0]}

	index1 := d.halfCoset.circleChip.uapi.ToValue(d.halfCoset.IndexAt(iBe).value)
	index2 := d.halfCoset.circleChip.uapi.ToValue(d.halfCoset.IndexAt(iMinSize).Neg().value)
	index := d.halfCoset.circleChip.api.Select(isLess, index1, index2)
	indexBytes, err := conversion.NativeToBytes(d.halfCoset.circleChip.api, index)
	if err != nil {
		panic(err)
	}
	resultValue := uints.U32{indexBytes[len(indexBytes)-1], indexBytes[len(indexBytes)-2], indexBytes[len(indexBytes)-3], indexBytes[len(indexBytes)-4]}
	return CirclePointIndex{circleChip: d.halfCoset.circleChip, value: resultValue}
}

// ╔══════════════════════════════════╗
// ║           Line Domain            ║
// ╚══════════════════════════════════╝

// LineDomain represents the projection of a given coset on x-axis.
type LineDomain struct {
	coset Coset
}

// NewLineDomain creates a new line domain.
func NewLineDomain(coset Coset) LineDomain {
	return LineDomain{
		coset: coset,
	}
}

// Coset returns the underlying coset.
func (d LineDomain) Coset() Coset {
	return d.coset
}

// Double returns the double of the line domain.
func (d LineDomain) Double() LineDomain {
	return NewLineDomain(d.coset.Double())
}

// LogSize returns the log size of the line domain.
func (d LineDomain) LogSize() frontend.Variable {
	return d.coset.logSize
}

// ╔══════════════════════════════════╗
// ║          Coset Vanishing         ║
// ╚══════════════════════════════════╝

// CosetVanishing evaluates the vanishing polynomial of a coset at point p.
func (c *CircleChip) CosetVanishing(coset Coset, p Point) m31.QM31 {
	x := p.X
	one := c.qm31.One()
	for i := 1; i < CircleLogOrder; i++ {
		isLess := c.comparator.IsLess(frontend.Variable(i), coset.LogSize())
		square := c.qm31.Mul(x, x)
		doubleSquare := c.qm31.Add(square, square)
		doubleSquareMinusOne := c.qm31.Sub(doubleSquare, one)
		x = c.qm31.Select(isLess, doubleSquareMinusOne, x)
	}
	return x
}

// CosetVanishingInverse returns the inverse of the vanishing evaluation.
func (c *CircleChip) CosetVanishingInverse(coset Coset, p Point) m31.QM31 {
	return c.qm31.Inverse(c.CosetVanishing(coset, p))
}

// CanonicVanishingInverse evaluates the canonic coset vanishing polynomial and inverts it.
func (c *CircleChip) CanonicVanishingInverse(logSize frontend.Variable, p Point) m31.QM31 {
	return c.CosetVanishingInverse(NewCanonicCoset(c, logSize).Coset(), p)
}
