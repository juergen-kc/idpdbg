//go:build cgo || windows

// PC/SC needs cgo on macOS (PCSC.framework) and Linux (pcsc-lite); on
// Windows the library loads winscard.dll without cgo.

package main

import "github.com/ebfe/scard"

type pcscConn struct {
	ctx  *scard.Context
	card *scard.Card
}

func (p *pcscConn) Transmit(cmd []byte) ([]byte, error) { return p.card.Transmit(cmd) }

func (p *pcscConn) Close() error {
	p.card.EndTransaction(scard.LeaveCard)
	p.card.Disconnect(scard.LeaveCard)
	return p.ctx.Release()
}

func init() {
	listReaders = func() ([]string, error) {
		ctx, err := scard.EstablishContext()
		if err != nil {
			return nil, err
		}
		defer ctx.Release()
		r, err := ctx.ListReaders()
		if err == scard.ErrNoReadersAvailable {
			return []string{}, nil
		}
		return r, err
	}
	connectCard = func(reader string) (cardConn, cardInfo, error) {
		ctx, err := scard.EstablishContext()
		if err != nil {
			return nil, cardInfo{}, err
		}
		card, err := ctx.Connect(reader, scard.ShareShared, scard.ProtocolAny)
		if err != nil {
			ctx.Release()
			return nil, cardInfo{}, err
		}
		if err := card.BeginTransaction(); err != nil {
			card.Disconnect(scard.LeaveCard)
			ctx.Release()
			return nil, cardInfo{}, err
		}
		info := cardInfo{Reader: reader}
		if st, err := card.Status(); err == nil {
			info.ATR = st.Atr
		}
		return &pcscConn{ctx: ctx, card: card}, info, nil
	}
}
