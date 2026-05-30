package postgres

import (
	"github.com/jackc/pgx/v5/pgxpool"
)

// Pools holds the primary (read-write) connection pool and an optional
// read-only replica pool. If ReadReplicaURL is empty in config, Reader
// is identical to Writer so existing code paths keep working unchanged.
//
// Repositories that want to opt-in to replica reads can take *Pools and
// pick which pool to use per query.
type Pools struct {
	Writer *pgxpool.Pool
	Reader *pgxpool.Pool
}

func (p *Pools) Close() {
	if p == nil {
		return
	}
	if p.Writer != nil {
		p.Writer.Close()
	}
	if p.Reader != nil && p.Reader != p.Writer {
		p.Reader.Close()
	}
}

func NewPools(writerURL, readerURL string) (*Pools, error) {
	w, err := New(writerURL)
	if err != nil {
		return nil, err
	}
	if readerURL == "" || readerURL == writerURL {
		return &Pools{Writer: w, Reader: w}, nil
	}
	r, err := New(readerURL)
	if err != nil {
		w.Close()
		return nil, err
	}
	return &Pools{Writer: w, Reader: r}, nil
}
