// SPDX-License-Identifier: BSD-3-Clause

package totp

import (
	"context"
	"errors"

	"github.com/go-authn/mfa"
)

// Factor turns a code somebody typed into a factor a policy can ask.
//
//	r, err := mfa.Verify(ctx, mfa.Policy{Count: 2, DistinctKinds: true},
//	    password.Factor(given, want),
//	    totp.Factor("dora", secret, code, verifier),
//	)
//
// ⛔ It is POSSESSION, not knowledge. The person proves they hold the thing
// the secret was enrolled into -- a phone, a hardware token -- and that is
// what makes it a second factor next to a password. A policy asking for
// distinct kinds is relying on this classification, so it is worth saying
// plainly that a code read aloud over the telephone is possession no longer.
//
// ⛔ The [Verifier] is required. Without one there is nothing to refuse a
// replay or to limit guessing -- a million codes, tried in well under a
// second -- and the factor used to fall back to [Verify] silently when given
// nil. A nil Verifier is a caller's mistake, and since an [mfa.Factor] has
// nowhere to return an error until it is asked, it is reported then, by
// Verify, for every code.
func Factor(name string, secret, code []byte, v *Verifier) mfa.Factor {
	return factor{name: name, secret: secret, code: code, v: v}
}

type factor struct {
	name   string
	secret []byte
	code   []byte
	v      *Verifier
}

func (f factor) Name() string   { return "your authenticator app" }
func (f factor) Kind() mfa.Kind { return mfa.Possession }

func (f factor) Verify(context.Context) error {
	// First, because it is the caller's mistake whatever the person did: an
	// unavailable answer here would let a policy pass on the other factors
	// and hide it.
	if f.v == nil {
		return errNoVerifier
	}
	// A person with no secret enrolled has not REFUSED anything: there was
	// nothing to ask. A policy counts that separately, and a server can then
	// say "you have no second factor" rather than "wrong code".
	if len(f.secret) == 0 {
		return mfa.Unavailable(errNoSecret)
	}
	return f.v.Verify(f.name, f.secret, f.code)
}

var errNoVerifier = errors.New("totp: a factor needs a *Verifier: " +
	"without one nothing refuses a replay or limits guessing")

var errNoSecret = errNoSecretType{}

type errNoSecretType struct{}

func (errNoSecretType) Error() string {
	return "totp: nobody enrolled an authenticator for this person"
}
