package verifier

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/blake2s"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
)

type VerifierChip struct {
	api         frontend.API `gnark:"-"`
	blake2sChip *blake2s.Blake2sChip
	m31Chip     *m31.M31Chip
	cm31Chip    *m31.CM31Chip
	qm31Chip    *m31.QM31Chip
}

func NewVerifierChip(api frontend.API) *VerifierChip {
	blake2sChip := blake2s.NewBlake2sChip(api)
	m31Chip := m31.NewM31Chip(api)
	cm31Chip := m31.NewCM31Chip(m31Chip)
	qm31Chip := m31.NewQM31Chip(cm31Chip)
	return &VerifierChip{
		api:         api,
		blake2sChip: blake2sChip,
		m31Chip:     m31Chip,
		cm31Chip:    cm31Chip,
		qm31Chip:    qm31Chip,
	}
}

func (c *VerifierChip) Verify() {

}
