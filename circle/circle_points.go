package circle

import (
	"math/big"

	"github.com/HerodotusDev/stwo-gnark-verifier/channel"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/HerodotusDev/stwo-gnark-verifier/utils"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/conversion"
	gnarkbits "github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/cmp"
	"github.com/consensys/gnark/std/math/uints"
)

const (
	CircleLogOrder = 31
)

var M31CircleOrderBitMask = uints.NewU32((1 << CircleLogOrder) - 1)

// ╔══════════════════════════════════╗
// ║            Circle Chip           ║
// ╚══════════════════════════════════╝

// CircleChip wires circle operations into the circuit.
type CircleChip struct {
	api        frontend.API
	uapi       *uints.BinaryField[uints.U32]
	comparator *cmp.BoundedComparator
	m31        *m31.M31Chip
	qm31       *m31.QM31Chip
}

// NewCircleChip instantiates a circle chip backed by the provided field chips.
func NewCircleChip(api frontend.API, m31Chip *m31.M31Chip, qm31Chip *m31.QM31Chip) *CircleChip {
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		panic(err)
	}
	comparator := cmp.NewBoundedComparator(api, big.NewInt(1<<32), false)

	return &CircleChip{
		api:        api,
		uapi:       uapi,
		comparator: comparator,
		m31:        m31Chip,
		qm31:       qm31Chip,
	}
}

// ╔══════════════════════════════════╗
// ║         QM31 Circle Point        ║
// ╚══════════════════════════════════╝

// Point represents a point on the secure circle.
type Point struct {
	X m31.QM31
	Y m31.QM31
}

// NewPoint builds a circle point from its coordinates.
func NewPoint(x, y m31.QM31) Point {
	return Point{X: x, Y: y}
}

// Add adds two circle points.
func (c *CircleChip) Add(p, q Point) Point {
	xx := c.qm31.Sub(c.qm31.Mul(p.X, q.X), c.qm31.Mul(p.Y, q.Y))
	yy := c.qm31.Add(c.qm31.Mul(p.X, q.Y), c.qm31.Mul(p.Y, q.X))
	return Point{X: xx, Y: yy}
}

// Add a base circle point to a circle point.
func (c *CircleChip) AddBasePoint(p Point, q BasePoint) Point {
	return Point{
		X: c.qm31.Sub(c.qm31.MulM31(p.X, q.X), c.qm31.MulM31(p.Y, q.Y)),
		Y: c.qm31.Add(c.qm31.MulM31(p.X, q.Y), c.qm31.MulM31(p.Y, q.X)),
	}
}

// Neg returns the antipode of a circle point.
func (c *CircleChip) Neg(p Point) Point {
	return Point{X: p.X, Y: c.qm31.Neg(p.Y)}
}

// Sub subtracts q from p.
func (c *CircleChip) Sub(p, q Point) Point {
	return c.Add(p, c.Neg(q))
}

// LiftBasePoint lifts a base-field circle point into the extension.
func (c *CircleChip) LiftBasePoint(p BasePoint) Point {
	return Point{
		X: m31.NewQM31FromM31(p.X),
		Y: m31.NewQM31FromM31(p.Y),
	}
}

// GetRandomPoint draws a random point on the secure circle from the channel.
func (c *CircleChip) GetRandomPoint(ch *channel.Channel) Point {
	t := ch.DrawFelt()
	tSquare := c.qm31.Mul(t, t)

	one := c.qm31.One()
	onePlusTSquaredInv := c.qm31.Inverse(c.qm31.Add(tSquare, one))

	x := c.qm31.Mul(c.qm31.Sub(one, tSquare), onePlusTSquaredInv)
	y := c.qm31.Mul(c.qm31.Add(t, t), onePlusTSquaredInv)

	return Point{X: x, Y: y}
}

// ╔══════════════════════════════════╗
// ║         M31 Circle Point         ║
// ╚══════════════════════════════════╝

// BasePoint represents a point on the base field circle.
type BasePoint struct {
	X m31.M31
	Y m31.M31
}

var (
	baseCircleZero      = NewBasePoint(m31.NewM31Unchecked(1), m31.NewM31Unchecked(0))
	baseCircleGenerator = NewBasePoint(m31.NewM31Unchecked(2), m31.NewM31Unchecked(0x4B94532F))
)

// NewBasePoint builds a circle point from its coordinates.
func NewBasePoint(x, y m31.M31) BasePoint {
	return BasePoint{X: x, Y: y}
}

// Add adds two base circle points.
func (c *CircleChip) BaseAdd(p, q BasePoint) BasePoint {
	xx := c.m31.Sub(c.m31.Mul(p.X, q.X), c.m31.Mul(p.Y, q.Y))
	yy := c.m31.Add(c.m31.Mul(p.X, q.Y), c.m31.Mul(p.Y, q.X))
	return BasePoint{X: xx, Y: yy}
}

// Neg negates a base circle point.
func (c *CircleChip) BaseNeg(p BasePoint) BasePoint {
	return BasePoint{X: p.X, Y: c.m31.Neg(p.Y)}
}

// BaseMul multiplies a base circle point by a scalar.
func (c *CircleChip) BaseMul(p BasePoint, scalar uints.U32) BasePoint {
	res := baseCircleZero
	scalarValue := c.uapi.ToValue(scalar)
	scalarBits := gnarkbits.ToBinary(c.api, scalarValue, gnarkbits.WithNbDigits(32))

	for i := len(scalarBits) - 1; i >= 0; i-- {
		res = c.BaseAdd(res, res)
		candidate := c.BaseAdd(res, p)
		res.X = m31.NewM31Unchecked(c.api.Select(scalarBits[i], candidate.X.Variable(), res.X.Variable()))
		res.Y = m31.NewM31Unchecked(c.api.Select(scalarBits[i], candidate.Y.Variable(), res.Y.Variable()))
	}
	return res
}

// ╔══════════════════════════════════╗
// ║         Circle Point Index       ║
// ╚══════════════════════════════════╝

// circlePointIndex tracks additive offsets on the circle.
type circlePointIndex struct {
	circleChip *CircleChip

	value uints.U32
}

// newPointIndex creates a new point index reducing with an And since group order is a power of two.
func newPointIndex(c *CircleChip, value uints.U32) circlePointIndex {
	return circlePointIndex{circleChip: c, value: c.uapi.And(value, M31CircleOrderBitMask)}
}

// Point returns the circle point corresponding to the index.
func (i circlePointIndex) Point() BasePoint {
	return i.circleChip.BaseMul(baseCircleGenerator, i.value)
}

// Neg returns the negation of the point index.
func (i circlePointIndex) Neg() circlePointIndex {
	order := frontend.Variable(uint32(1) << CircleLogOrder)
	valueNative := i.circleChip.uapi.ToValue(i.value)
	unreducedNewValue := i.circleChip.api.Sub(order, valueNative)
	unreducedNewValueBytes, err := conversion.NativeToBytes(i.circleChip.api, unreducedNewValue)
	if err != nil {
		panic(err)
	}
	negValue := uints.U32{unreducedNewValueBytes[len(unreducedNewValueBytes)-1], unreducedNewValueBytes[len(unreducedNewValueBytes)-2], unreducedNewValueBytes[len(unreducedNewValueBytes)-3], unreducedNewValueBytes[len(unreducedNewValueBytes)-4]}
	negValue = i.circleChip.uapi.And(negValue, M31CircleOrderBitMask)
	return circlePointIndex{circleChip: i.circleChip, value: negValue}
}

func (i circlePointIndex) Mul(scalar uints.U32) circlePointIndex {
	scalarNative := i.circleChip.uapi.ToValue(scalar)
	indexNative := i.circleChip.uapi.ToValue(i.value)
	unreducedNewValue := i.circleChip.api.Mul(indexNative, scalarNative)
	unreducedNewValueBytes, err := conversion.NativeToBytes(i.circleChip.api, unreducedNewValue)
	if err != nil {
		panic(err)
	}
	reducedNewValue := uints.U32{unreducedNewValueBytes[len(unreducedNewValueBytes)-1], unreducedNewValueBytes[len(unreducedNewValueBytes)-2], unreducedNewValueBytes[len(unreducedNewValueBytes)-3], unreducedNewValueBytes[len(unreducedNewValueBytes)-4]}
	reducedNewValue = i.circleChip.uapi.And(reducedNewValue, M31CircleOrderBitMask)
	return circlePointIndex{circleChip: i.circleChip, value: reducedNewValue}
}

func (c *CircleChip) AddPointIndex(a, b circlePointIndex) circlePointIndex {
	unreducedSum := c.uapi.Add(a.value, b.value)
	reducedSum := c.uapi.And(unreducedSum, M31CircleOrderBitMask)
	return circlePointIndex{circleChip: c, value: reducedSum}
}

func SubgroupGenerator(circleChip *CircleChip, logSize frontend.Variable) circlePointIndex {
	expNative := circleChip.api.Sub(frontend.Variable(CircleLogOrder), logSize)
	twoPowExp := utils.Pow(circleChip.api, circleChip.comparator, frontend.Variable(2), expNative)
	pointIndexU32 := circleChip.uapi.ValueOf(twoPowExp)
	return newPointIndex(circleChip, pointIndexU32)
}

// ╔══════════════════════════════════╗
// ║       Coset Vanishing Helpers    ║
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
