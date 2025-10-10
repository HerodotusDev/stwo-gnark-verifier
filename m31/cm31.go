package m31

import "github.com/consensys/gnark/frontend"

// ╔══════════════════════════════════╗
// ║        CM31 Field Element        ║
// ╚══════════════════════════════════╝

// CM31 represents an element of the complex extension of M31: a + bi.
type CM31 struct {
	A M31
	B M31
}

// ╔══════════════════════════════════╗
// ║          CM31 Chip Logic         ║
// ╚══════════════════════════════════╝

// CM31Chip exposes arithmetic over CM31 elements by reusing the base M31 chip.
type CM31Chip struct {
	m31 *M31Chip
}

// NewCM31Chip creates a CM31 chip backed by the provided M31 chip.
func NewCM31Chip(m31 *M31Chip) *CM31Chip {
	return &CM31Chip{m31: m31}
}

// NewCM31 builds a CM31 element from its components.
func NewCM31(a, b M31) CM31 {
	return CM31{A: a, B: b}
}

// CM31FromM31 lifts a base element into the extension.
func (c *CM31Chip) CM31FromM31(x M31) CM31 {
	return CM31{A: x, B: Zero()}
}

// Zero returns the additive identity.
func (c *CM31Chip) Zero() CM31 {
	return CM31{A: Zero(), B: Zero()}
}

// One returns the multiplicative identity.
func (c *CM31Chip) One() CM31 {
	return CM31{A: One(), B: Zero()}
}

// Neg returns -x.
func (c *CM31Chip) Neg(x CM31) CM31 {
	return CM31{
		A: c.m31.Sub(Zero(), x.A),
		B: c.m31.Sub(Zero(), x.B),
	}
}

// Add computes x + y.
func (c *CM31Chip) Add(x, y CM31) CM31 {
	return CM31{
		A: c.m31.Add(x.A, y.A),
		B: c.m31.Add(x.B, y.B),
	}
}

// AddUnchecked computes x + y without reducing the result.
func (c *CM31Chip) AddUnchecked(x, y CM31) CM31 {
	return CM31{
		A: c.m31.AddUnchecked(x.A, y.A),
		B: c.m31.AddUnchecked(x.B, y.B),
	}
}

// Sub computes x - y.
func (c *CM31Chip) Sub(x, y CM31) CM31 {
	return CM31{
		A: c.m31.Sub(x.A, y.A),
		B: c.m31.Sub(x.B, y.B),
	}
}

// SubUnchecked computes x - y without reducing the result.
func (c *CM31Chip) SubUnchecked(x, y CM31) CM31 {
	return CM31{
		A: c.m31.SubUnchecked(x.A, y.A),
		B: c.m31.SubUnchecked(x.B, y.B),
	}
}

// Mul computes (a + bi)(c + di).
func (c *CM31Chip) Mul(x, y CM31) CM31 {
	ac := c.m31.Mul(x.A, y.A)
	bd := c.m31.Mul(x.B, y.B)
	ad := c.m31.Mul(x.A, y.B)
	bc := c.m31.Mul(x.B, y.A)

	return CM31{
		A: c.m31.Sub(ac, bd),
		B: c.m31.Add(ad, bc),
	}
}

// MulUnchecked multiplies without reducing intermediate terms.
func (c *CM31Chip) MulUnchecked(x, y CM31) CM31 {
	ac := c.m31.MulUnchecked(x.A, y.A)
	bd := c.m31.MulUnchecked(x.B, y.B)
	ad := c.m31.MulUnchecked(x.A, y.B)
	bc := c.m31.MulUnchecked(x.B, y.A)

	return CM31{
		A: c.m31.SubUnchecked(ac, bd),
		B: c.m31.AddUnchecked(ad, bc),
	}
}

// MulM31 multiplies by a base element.
func (c *CM31Chip) MulM31(x CM31, m M31) CM31 {
	return CM31{
		A: c.m31.Mul(x.A, m),
		B: c.m31.Mul(x.B, m),
	}
}

// MulM31Unchecked multiplies by a base element without reducing.
func (c *CM31Chip) MulM31Unchecked(x CM31, m M31) CM31 {
	return CM31{
		A: c.m31.MulUnchecked(x.A, m),
		B: c.m31.MulUnchecked(x.B, m),
	}
}

// Inverse computes 1/x (fails if x = 0)
func (c *CM31Chip) Inverse(x CM31) CM31 {
	aSq := c.m31.Mul(x.A, x.A)
	bSq := c.m31.Mul(x.B, x.B)
	denom := c.m31.Add(aSq, bSq)

	denomInv, hasInv := c.m31.Inverse(denom)
	c.m31.api.AssertIsEqual(hasInv, frontend.Variable(1))

	return CM31{
		A: c.m31.Mul(x.A, denomInv),
		B: c.m31.Mul(c.m31.Sub(Zero(), x.B), denomInv),
	}
}

// BatchInverse returns the component-wise inverse of every element.
func (c *CM31Chip) BatchInverse(values []CM31) []CM31 {
	n := len(values)
	if n == 0 {
		return nil
	}

	prefix := make([]CM31, n)
	prefix[0] = values[0]
	for i := 1; i < n; i++ {
		prefix[i] = c.Mul(prefix[i-1], values[i])
	}

	totalInverse := c.Inverse(prefix[n-1])
	inverses := make([]CM31, n)
	inverses[n-1] = totalInverse

	curr := totalInverse
	for i := n - 1; i >= 1; i-- {
		inverses[i] = c.Mul(prefix[i-1], curr)
		curr = c.Mul(curr, values[i])
	}
	inverses[0] = curr
	return inverses
}
