package circle

import (
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

	initial circlePointIndex
	step    circlePointIndex
	logSize uint32
}

// newCoset builds a coset whose step size is the subgroup generator of logSize.
func NewCoset(circleChip *CircleChip, initial circlePointIndex, logSize uint32) Coset {
	if logSize == 0 || logSize > CircleLogOrder {
		panic("unsupported coset log size")
	}
	stepSize := SubgroupGenerator(circleChip, logSize)
	return Coset{
		circleChip: circleChip,
		initial:    initial,
		step:       stepSize,
		logSize:    logSize,
	}
}

func (c Coset) halfOdds(logSize uint32) Coset {
	return NewCoset(c.circleChip, SubgroupGenerator(c.circleChip, logSize+2), logSize)
}

func (c Coset) Double() Coset {
	return NewCoset(c.circleChip, c.initial.Mul(uints.NewU32(2)), c.logSize-1)
}

func (c Coset) IndexAt(i uints.U32) circlePointIndex {
	return c.circleChip.AddPointIndex(c.initial, c.step.Mul(i))
}

// LogSize returns the coset log size.
func (c Coset) LogSize() uint32 {
	return c.logSize
}

func (c Coset) Size() uint32 {
	return uint32(1) << c.logSize
}

func (c Coset) Step() circlePointIndex {
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
func NewCanonicCoset(circleChip *CircleChip, logSize uint32) CanonicCoset {
	if logSize == 0 || logSize >= CircleLogOrder {
		panic("invalid canonic coset log size")
	}
	initial := SubgroupGenerator(circleChip, logSize+1)
	return CanonicCoset{
		coset: NewCoset(circleChip, initial, logSize),
	}
}

// halfCoset returns half of coset.
func (c CanonicCoset) HalfCoset() Coset {
	return c.coset.halfOdds(c.LogSize() - 1)
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
func (c CanonicCoset) LogSize() uint32 {
	return c.coset.logSize
}

// ╔══════════════════════════════════╗
// ║           Circle Domain          ║
// ╚══════════════════════════════════╝
type CircleDomain struct {
	halfCoset Coset
}

func NewCircleDomain(halfCoset Coset) CircleDomain {
	return CircleDomain{
		halfCoset: halfCoset,
	}
}

func (d CircleDomain) LogSize() uint32 {
	return d.halfCoset.logSize + 1
}

func (d CircleDomain) At(i uints.U32) BasePoint {
	return d.IndexAt(i).Point()
}

func (d CircleDomain) IndexAt(i uints.U32) circlePointIndex {
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
	return circlePointIndex{circleChip: d.halfCoset.circleChip, value: resultValue}
}

// ╔══════════════════════════════════╗
// ║           Line Domain            ║
// ╚══════════════════════════════════╝
type LineDomain struct {
	coset Coset
}

func NewLineDomain(coset Coset) LineDomain {
	return LineDomain{
		coset: coset,
	}
}

func (d LineDomain) Double() LineDomain {
	return NewLineDomain(d.coset.Double())
}
