package m31

// ╔══════════════════════════════════╗
// ║        QM31 Field Element        ║
// ╚══════════════════════════════════╝

// QM31 represents an element of the quadratic extension over CM31: a + u b.
type QM31 struct {
	A CM31
	B CM31
}

// qm31R = 2 + i = u^2.
var qm31R = NewCM31(NewM31Unchecked(2), NewM31Unchecked(1))

// ╔══════════════════════════════════╗
// ║          QM31 Chip Logic         ║
// ╚══════════════════════════════════╝

// QM31Chip exposes arithmetic for QM31 elements.
type QM31Chip struct {
	cm31 *CM31Chip
}

// NewQM31Chip builds a QM31 chip from the underlying CM31 chip.
func NewQM31Chip(cm31 *CM31Chip) *QM31Chip {
	return &QM31Chip{cm31: cm31}
}

// Zero returns the additive identity.
func (q *QM31Chip) Zero() QM31 {
	return QM31{A: q.cm31.Zero(), B: q.cm31.Zero()}
}

// One returns the multiplicative identity.
func (q *QM31Chip) One() QM31 {
	return QM31{A: q.cm31.One(), B: q.cm31.Zero()}
}

// FromCM31 lifts a CM31 element into the extension.
func (q *QM31Chip) FromCM31(x CM31) QM31 {
	return QM31{A: x, B: q.cm31.Zero()}
}

// FromM31 lifts an M31 element into the extension.
func (q *QM31Chip) FromM31(x M31) QM31 {
	return q.FromCM31(q.cm31.CM31FromM31(x))
}

// Neg returns -x.
func (q *QM31Chip) Neg(x QM31) QM31 {
	return QM31{A: q.cm31.Neg(x.A), B: q.cm31.Neg(x.B)}
}

// Add computes x + y.
func (q *QM31Chip) Add(x, y QM31) QM31 {
	return QM31{
		A: q.cm31.Add(x.A, y.A),
		B: q.cm31.Add(x.B, y.B),
	}
}

// AddUnchecked computes x + y without reducing the result.
func (q *QM31Chip) AddUnchecked(x, y QM31) QM31 {
	return QM31{
		A: q.cm31.AddUnchecked(x.A, y.A),
		B: q.cm31.AddUnchecked(x.B, y.B),
	}
}

// Sub computes x - y.
func (q *QM31Chip) Sub(x, y QM31) QM31 {
	return QM31{
		A: q.cm31.Sub(x.A, y.A),
		B: q.cm31.Sub(x.B, y.B),
	}
}

// SubUnchecked computes x - y without reducing.
func (q *QM31Chip) SubUnchecked(x, y QM31) QM31 {
	return QM31{
		A: q.cm31.SubUnchecked(x.A, y.A),
		B: q.cm31.SubUnchecked(x.B, y.B),
	}
}

// Mul computes (a + u b)(c + u d) with u^2 = 2 + i.
func (q *QM31Chip) Mul(lhs, rhs QM31) QM31 {
	ac := q.cm31.Mul(lhs.A, rhs.A)
	bd := q.cm31.Mul(lhs.B, rhs.B)
	rbd := q.cm31.Mul(qm31R, bd)
	ad := q.cm31.Mul(lhs.A, rhs.B)
	bc := q.cm31.Mul(lhs.B, rhs.A)

	return QM31{
		A: q.cm31.Add(ac, rbd),
		B: q.cm31.Add(ad, bc),
	}
}

// MulUnchecked multiplies without reducing intermediate terms.
func (q *QM31Chip) MulUnchecked(lhs, rhs QM31) QM31 {
	ac := q.cm31.MulUnchecked(lhs.A, rhs.A)
	bd := q.cm31.MulUnchecked(lhs.B, rhs.B)
	rbd := q.cm31.MulUnchecked(qm31R, bd)
	ad := q.cm31.MulUnchecked(lhs.A, rhs.B)
	bc := q.cm31.MulUnchecked(lhs.B, rhs.A)

	return QM31{
		A: q.cm31.AddUnchecked(ac, rbd),
		B: q.cm31.AddUnchecked(ad, bc),
	}
}

// MulCM31 multiplies by a CM31 element.
func (q *QM31Chip) MulCM31(x QM31, y CM31) QM31 {
	return QM31{
		A: q.cm31.Mul(x.A, y),
		B: q.cm31.Mul(x.B, y),
	}
}

// MulCM31Unchecked multiplies by a CM31 element without reducing.
func (q *QM31Chip) MulCM31Unchecked(x QM31, y CM31) QM31 {
	return QM31{
		A: q.cm31.MulUnchecked(x.A, y),
		B: q.cm31.MulUnchecked(x.B, y),
	}
}

// MulM31 multiplies by a base M31 element.
func (q *QM31Chip) MulM31(x QM31, m M31) QM31 {
	return QM31{
		A: q.cm31.MulM31(x.A, m),
		B: q.cm31.MulM31(x.B, m),
	}
}

// MulM31Unchecked multiplies by an M31 element without reducing.
func (q *QM31Chip) MulM31Unchecked(x QM31, m M31) QM31 {
	return QM31{
		A: q.cm31.MulM31Unchecked(x.A, m),
		B: q.cm31.MulM31Unchecked(x.B, m),
	}
}

// Inverse computes 1/x.
func (q *QM31Chip) Inverse(x QM31) QM31 {
	b2 := q.cm31.Mul(x.B, x.B)
	negB2Imag := q.cm31.m31.Sub(Zero(), b2.B)
	ib2 := CM31{A: negB2Imag, B: b2.A}
	doubledB2 := q.cm31.Add(b2, b2)
	sum := q.cm31.Add(doubledB2, ib2)
	aSquared := q.cm31.Mul(x.A, x.A)
	denom := q.cm31.Sub(aSquared, sum)

	denomInv := q.cm31.Inverse(denom)

	return QM31{
		A: q.cm31.Mul(x.A, denomInv),
		B: q.cm31.Neg(q.cm31.Mul(x.B, denomInv)),
	}
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
