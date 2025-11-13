package circle

// ╔══════════════════════════════════╗
// ║              Coset               ║
// ╚══════════════════════════════════╝

// Coset represents initial + <step>.
// Since column sizes are known at circuit compile time, logSize is a uint32
type Coset struct {
	initial circlePointIndex
	step    circlePointIndex
	logSize uint32
}

// newCoset builds a coset whose step size is the subgroup generator of logSize.
func (c *CircleChip) newCoset(initial circlePointIndex, logSize uint32) Coset {
	if logSize == 0 || logSize > CircleLogOrder {
		panic("unsupported coset log size")
	}
	stepSize := c.subgroupGenerator(logSize)
	return Coset{
		initial: initial,
		step:    stepSize,
		logSize: logSize,
	}
}

// LogSize returns the coset log size.
func (c Coset) LogSize() uint32 {
	return c.logSize
}

// ╔══════════════════════════════════╗
// ║           Canonic Coset          ║
// ╚══════════════════════════════════╝

// CanonicCoset denotes G_{2n} + <G_n>.
type CanonicCoset struct {
	coset Coset
}

// NewCanonicCoset creates a canonic coset of size 2^logSize.
func (c *CircleChip) NewCanonicCoset(logSize uint32) CanonicCoset {
	if logSize == 0 || logSize >= CircleLogOrder {
		panic("invalid canonic coset log size")
	}
	initial := c.subgroupGenerator(logSize + 1)
	return CanonicCoset{
		coset: c.newCoset(initial, logSize),
	}
}

// Coset returns the underlying coset.
func (c CanonicCoset) Coset() Coset {
	return c.coset
}

// LogSize returns the coset log size.
func (c CanonicCoset) LogSize() uint32 {
	return c.coset.logSize
}
