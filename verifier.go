// SPDX-License-Identifier: BSD-3-Clause

package totp

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"time"
)

// A Verifier is [Verify] plus the things a server needs and a function cannot
// have: a memory of which codes were already used, and of how many wrong ones
// each name has sent.
//
// ⛔ A code is valid for a whole step. Without this, somebody who watches one
// being typed -- over a shoulder, in a log, on a wire that was not TLS -- can
// use it themselves for the rest of that half-minute. RFC 6238 §5.2: the
// verifier MUST NOT accept a second attempt of an OTP that already succeeded.
//
// ⛔ And a code has only a million values. Without a limit, trying them all
// against one name takes well under a second; RFC 4226 §7.3 says the server
// needs to detect and stop that, and NIST SP 800-63B §5.2.2 says it SHALL
// limit consecutive failed attempts to no more than 100. So:
//
//   - after [Verifier.Throttle] wrong codes in a row for a name, that name is
//     refused with [ErrThrottled] -- without its code being looked at, so even
//     the right one -- until [Verifier.Pause] has passed;
//   - after [Verifier.Lockout] wrong codes in a row, however spread out, it is
//     refused with [ErrLockedOut] until [Verifier.Forget] is called for it.
//
// Only a wrong code counts: a replay, a code of the wrong length, a refused
// secret or parameters that cannot work are refused for their own reasons. A
// code that is accepted starts the count again. With the defaults, somebody
// guessing gets 100 tries in about five hours and then none: with the default
// window of three steps that is a chance of 3 in 10,000 for six digits.
//
// ⛔ The memory is per CREDENTIAL -- per secret -- not per name. It was per
// name, and the name is whatever string the caller passes: a login form that
// does not canonicalise gave "dora", "Dora", "DORA" ... sixteen counters for
// one secret, and 1,600 guesses where the lockout said 100. What a guesser
// attacks is the secret, so that is what the count follows. A replay is
// refused per secret too, which is what RFC 6238 §5.2 asks: the code accepted
// was the secret's, under whatever name it was typed. The secret is held only
// as its SHA-256.
//
// The name is still remembered, beside the credential it last presented, for
// one purpose: [Verifier.Forget] takes a name.
//
// The memory is this process's. Two servers behind a load
// balancer each count their own guesses and neither knows about the other's;
// a deployment that needs one answer needs a shared store, and this is the
// interface to put one behind. A credential nobody has tried for a day is
// forgotten, and so is a name, so a stream of either cannot grow it for ever
// -- except a credential that is locked out, because forgetting that would be
// an unlock.
//
// The zero Verifier works, with the default options and limits.
type Verifier struct {
	Options Options

	// Throttle is how many wrong codes in a row a name may send before it
	// is made to wait. Zero or less means [DefaultThrottle].
	Throttle int
	// Pause is how long it waits. Zero or less means [DefaultPause].
	Pause time.Duration
	// Lockout is how many wrong codes in a row lock a name out until
	// [Verifier.Forget]. Zero or less means [DefaultLockout].
	Lockout int

	mu      sync.Mutex
	creds   map[credential]*state
	names   map[string]alias
	sweepAt int
}

// credential is what the state is kept under: the SHA-256 of a secret.
type credential [sha256.Size]byte

// alias is a name and the credential it last presented, for [Verifier.Forget].
type alias struct {
	cred credential
	seen time.Time
}

// The defaults. RFC 4226 §7.3 asks for a throttling parameter "as low as
// possible, while still ensuring that usability is not significantly
// impacted" and names none; five is a person mistyping more than they ever
// do. NIST SP 800-63B §5.2.2 sets the ceiling the lockout sits on.
const (
	DefaultThrottle = 5
	DefaultPause    = 15 * time.Minute
	DefaultLockout  = 100
)

// idle is how long a name nobody tries is remembered.
const idle = 24 * time.Hour

// state is what is remembered about one credential.
type state struct {
	accepted bool      // whether step means anything
	step     int64     // the last step accepted
	failures int       // wrong codes in a row
	until    time.Time // refused before this, after a throttle
	seen     time.Time // the last attempt that was looked at
}

func (v *Verifier) throttle() int {
	if v.Throttle <= 0 {
		return DefaultThrottle
	}
	return v.Throttle
}

func (v *Verifier) pause() time.Duration {
	if v.Pause <= 0 {
		return DefaultPause
	}
	return v.Pause
}

func (v *Verifier) lockout() int {
	if v.Lockout <= 0 {
		return DefaultLockout
	}
	return v.Lockout
}

// Verify checks a code for one person and refuses one that was already used,
// and refuses to look at all while that person's credential is throttled or
// locked out.
//
// The name is whatever the caller calls people. It does not have to be
// canonical: what is counted is the secret, under every spelling of the name.
// It is what [Verifier.Forget] is later called with.
//
// ⛔ The whole check is made under one lock. RFC 4226 §7.3: the limit MUST
// hold "to prevent attacks based on multiple parallel guessing techniques",
// and a count read before the code is checked and written after lets every
// guess sent at the same moment find it below the limit. The price is that
// one Verifier checks one code at a time: three HMACs, microseconds.
func (v *Verifier) Verify(name string, secret, code []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	now := v.Options.now()
	key := credential(sha256.Sum256(secret))
	s := v.creds[key]
	if s != nil {
		// Remembered even when refused: the person locked out is the one
		// whose name Forget will be called with.
		v.names[name] = alias{key, now}
		if s.failures >= v.lockout() {
			return ErrLockedOut
		}
		if now.Before(s.until) {
			return ErrThrottled
		}
	}

	step, err := verifyStep(secret, code, v.Options)
	if err != nil && !errors.Is(err, ErrWrongCode) {
		// Not a guess: nothing is counted and nothing is remembered.
		return err
	}
	if s == nil {
		s = v.remember(key, now)
	}
	v.names[name] = alias{key, now}
	s.seen = now
	if err != nil {
		s.failures++
		if s.failures < v.lockout() && s.failures%v.throttle() == 0 {
			s.until = now.Add(v.pause())
		}
		return err
	}
	// Not just "the same step twice": every step up to and including the last
	// accepted one is refused. Otherwise a code from thirty seconds ago, still
	// inside the window, is a valid second answer -- which is the same replay
	// with one more step of patience. A replay is not a guess, and is not
	// counted as one.
	if s.accepted && step <= s.step {
		return ErrUsed
	}
	s.accepted, s.step, s.failures, s.until = true, step, 0, time.Time{}
	return nil
}

// remember makes room for a credential, forgetting idle ones -- and idle
// names -- when the maps have doubled since the last time it looked: the cost
// of looking is spread over what was added, and the maps are never more than
// about twice what is live.
func (v *Verifier) remember(key credential, now time.Time) *state {
	if v.creds == nil {
		v.creds = map[credential]*state{}
		v.names = map[string]alias{}
	}
	if len(v.creds)+len(v.names) >= v.sweepAt {
		// A step accepted at the far edge of the window is still a replay
		// risk for two windows' worth of steps; a day covers that unless
		// the period is enormous, and then the window decides.
		keep := max(idle, v.pause(), time.Duration(2*v.Options.window()+2)*v.Options.period())
		for k, s := range v.creds {
			if s.failures < v.lockout() && now.Sub(s.seen) > keep {
				delete(v.creds, k)
			}
		}
		for n, a := range v.names {
			if now.Sub(a.seen) > keep {
				delete(v.names, n)
			}
		}
		v.sweepAt = max(1024, 2*(len(v.creds)+len(v.names)))
	}
	s := &state{}
	v.creds[key] = s
	return s
}

// Forget drops what is remembered about the credential a name last presented
// -- for a person removed from a directory, an administrator unlocking an
// account after [ErrLockedOut], or a test that means to start again.
//
// A name is remembered for a day after it was last tried, refused or not, so a
// person who was locked out and tried again is found under the name they used.
func (v *Verifier) Forget(name string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if a, ok := v.names[name]; ok {
		delete(v.creds, a.cred)
		delete(v.names, name)
	}
}

// ErrUsed is a code that was right and has already been accepted. It is
// distinct from [ErrWrongCode] because the two mean different things TO A
// SERVER -- one is a replay, worth noticing -- while a client is told the same
// thing either way.
var ErrUsed = fmt.Errorf("totp: that code has already been used")

// ErrThrottled is a name that sent too many wrong codes in a row and must
// wait before another is looked at. The code given with it was not checked,
// so it says nothing about whether that code was right.
var ErrThrottled = errors.New("totp: too many wrong codes in a row")

// ErrLockedOut is a name that sent [Verifier.Lockout] wrong codes in a row. It
// does not pass with time: [Verifier.Forget] is the way back, and it belongs
// to whoever can tell the person from somebody guessing. errors.Is reports it
// as [ErrThrottled] too, so a caller that only checks for that refuses it.
var ErrLockedOut = fmt.Errorf("%w; locked out until reset", ErrThrottled)
