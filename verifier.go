// SPDX-License-Identifier: BSD-3-Clause

package totp

import (
	"fmt"
	"sync"
)

// A Verifier is [Verify] plus the thing a server needs and a function cannot
// have: a memory of which codes were already used.
//
// ⛔ A code is valid for a whole step. Without this, somebody who watches one
// being typed -- over a shoulder, in a log, on a wire that was not TLS -- can
// use it themselves for the rest of that half-minute. RFC 6238 §5.2: the
// verifier MUST NOT accept a second attempt of an OTP that already succeeded.
//
// The memory is per NAME, and it is this process's. Two servers behind a load
// balancer each refuse their own replays and neither knows about the other's;
// a deployment that needs one answer needs a shared store, and this is the
// interface to put one behind.
//
// The zero Verifier works, with the default options.
type Verifier struct {
	Options Options

	mu   sync.Mutex
	last map[string]int64
}

// Verify checks a code for one person and refuses one that was already used.
//
// The name is whatever the caller calls people, and it only has to be stable:
// it is a map key here and nothing else.
func (v *Verifier) Verify(name string, secret, code []byte) error {
	step, err := verifyStep(secret, code, v.Options)
	if err != nil {
		return err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.last == nil {
		v.last = map[string]int64{}
	}
	// Not just "the same step twice": every step up to and including the last
	// accepted one is refused. Otherwise a code from thirty seconds ago, still
	// inside the window, is a valid second answer -- which is the same replay
	// with one more step of patience.
	if seen, ok := v.last[name]; ok && step <= seen {
		return ErrUsed
	}
	v.last[name] = step
	return nil
}

// Forget drops what is remembered about a name -- for a person removed from a
// directory, or a test that means to start again.
func (v *Verifier) Forget(name string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	delete(v.last, name)
}

// ErrUsed is a code that was right and has already been accepted. It is
// distinct from [ErrWrongCode] because the two mean different things TO A
// SERVER -- one is a replay, worth noticing -- while a client is told the same
// thing either way.
var ErrUsed = fmt.Errorf("totp: that code has already been used")
