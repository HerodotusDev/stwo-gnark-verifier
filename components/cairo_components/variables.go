package cairo_components

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

const (
	PREPROCESSED_IDX = 0
	MAIN_IDX         = 1
	INTERACTION_IDX  = 2
	CP_IDX           = 3
	N_TREES          = 4
)

// Traces encapsulates the sampled values for preprocessed, main trace
// and interaction domains while keeping track of consumption as
// components advance through evaluation.
type Traces struct {
	preprocessed PreprocessedSampledValues
	main         [][]m31.QM31
	interaction  [][]m31.QM31
}

// NewTraces builds a Traces helper from the sampled values.
func NewTraces(preprocessed PreprocessedSampledValues, main [][]m31.QM31, interaction [][]m31.QM31) *Traces {
	return &Traces{
		preprocessed: preprocessed,
		main:         main,
		interaction:  interaction,
	}
}

// RemainingMain returns the number of trace columns left to consume.
func (t *Traces) RemainingMain() int {
	return len(t.main)
}

// RemainingInteraction returns the number of interaction columns left.
func (t *Traces) RemainingInteraction() int {
	return len(t.interaction)
}

// Take returns the next main and interaction columns and advances the
// internal cursors. It panics if insufficient data is available.
func (t *Traces) Take(mainCols, interactionCols int) (Trace, InteractionTrace) {
	if mainCols < 0 || interactionCols < 0 {
		panic("trace consumption counts must be non-negative")
	}
	if len(t.main) < mainCols {
		panic("insufficient trace columns for component evaluation")
	}
	if len(t.interaction) < interactionCols {
		panic("insufficient interaction columns for component evaluation")
	}

	main := t.main[:mainCols]
	interaction := t.interaction[:interactionCols]

	t.main = t.main[mainCols:]
	t.interaction = t.interaction[interactionCols:]

	return Trace(main), InteractionTrace(interaction)
}

// Get returns the sampled value for the provided preprocessed column.
func (t *Traces) Get(column PreprocessedColumn) m31.QM31 {
	return t.preprocessed.Get(column)
}

// ╔══════════════════════════════════╗
// ║            Trace Views           ║
// ╚══════════════════════════════════╝

// Trace provides helpers to access main trace columns safely.
type Trace [][]m31.QM31

// InteractionTrace provides helpers to access interaction trace columns.
type InteractionTrace [][]m31.QM31

// Get returns the first sampled value of the specified main trace column.
func (tr Trace) Get(index int) m31.QM31 {
	if index < 0 || index >= len(tr) {
		panic("trace index out of range")
	}
	col := tr[index]
	if len(col) == 0 {
		panic("missing trace sample")
	}
	return col[0]
}

// Slice returns a slice of first-sample values from start for count columns.
func (tr Trace) Slice(start, count int) []m31.QM31 {
	if count < 0 || start < 0 || start+count > len(tr) {
		panic("trace slice out of range")
	}
	out := make([]m31.QM31, count)
	for i := 0; i < count; i++ {
		out[i] = tr.Get(start + i)
	}
	return out
}

// Partial builds a QM31 partial evaluation from 4 consecutive interaction columns.
// It uses the value at "offset" in each of the four columns starting at "start".
func (it InteractionTrace) Partial(q *m31.QM31Chip, start, offset int) m31.QM31 {
	if start < 0 || start+3 >= len(it) {
		panic("interaction partial start out of range")
	}
	a := it[start]
	b := it[start+1]
	c := it[start+2]
	d := it[start+3]
	if len(a) <= offset || len(b) <= offset || len(c) <= offset || len(d) <= offset {
		panic("missing interaction value for partial evaluation")
	}
	return q.FromPartialEvals(a[offset], b[offset], c[offset], d[offset])
}
