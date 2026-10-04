package totp_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-authn/mfa"
	"github.com/go-authn/totp"
)

// A code, asked as a factor next to something else.
func TestTheFactorSatisfiesAPolicy(t *testing.T) {
	secret := []byte("12345678901234567890")
	at := time.Unix(1111111109, 0)
	v := &totp.Verifier{Options: totp.Options{Now: func() time.Time { return at }}}
	code, err := totp.At(secret, at, v.Options)
	if err != nil {
		t.Fatal(err)
	}

	// Two factors of two kinds: what "two-factor" is normally taken to mean.
	r, err := mfa.Verify(context.Background(), mfa.Policy{Count: 2, DistinctKinds: true},
		knows("her password", nil), totp.Factor("dora", secret, []byte(code), v))
	if err != nil {
		t.Fatalf("a right password and a right code did not satisfy the policy: %v (%s)", err, r)
	}

	// ⛔ POSSESSION, not knowledge: it is what makes the code a SECOND factor
	// next to a password, and a policy asking for distinct kinds relies on it.
	f := totp.Factor("dora", secret, []byte(code), v)
	if f.Kind() != mfa.Possession {
		t.Errorf("the factor is %s, want possession", f.Kind())
	}
	if f.Name() == "" {
		t.Error("the factor has no name to tell a person")
	}

	// The same code again is a replay, and the policy is not satisfied.
	if _, err := mfa.Verify(context.Background(), mfa.Policy{Count: 2, DistinctKinds: true},
		knows("her password", nil), totp.Factor("dora", secret, []byte(code), v)); err == nil {
		t.Error("the same code satisfied the policy twice")
	}
}

// ⛔ A person with no authenticator enrolled has REFUSED nothing: there was
// nothing to ask. A policy counts that separately, so a server can say "you
// have no second factor" rather than "wrong code".
func TestNobodyEnrolledIsNotARefusal(t *testing.T) {
	f := totp.Factor("dora", nil, []byte("123456"), &totp.Verifier{})
	err := f.Verify(context.Background())
	if !errors.Is(err, mfa.ErrUnavailable) {
		t.Errorf("a person with no secret gave %v, want unavailable", err)
	}
	if !strings.Contains(err.Error(), "enrolled") {
		t.Errorf("the reason was lost: %q", err)
	}
	r, err := mfa.Verify(context.Background(), mfa.Policy{Count: 1},
		f, knows("her password", nil))
	if err != nil {
		t.Fatalf("a policy of one factor was not satisfied by the password: %v", err)
	}
	if !r.Answers[0].Unavailable() {
		t.Error("the answer does not read as unavailable")
	}
}

// ⛔ A factor with no Verifier is refused, every time, whatever code it holds.
// It used to fall back to the stateless check: no throttle, no lockout, no
// replay refusal -- an audit found the code after 236,089 wrong guesses in a
// quarter of a second, then replayed it three times. A nil Verifier is the
// caller's mistake, reported when the factor is asked, and it is not
// "unavailable": a policy must not pass on the other factors and hide it.
func TestAFactorWithoutAVerifierIsRefusedForEveryCode(t *testing.T) {
	secret := []byte("12345678901234567890")
	code, err := totp.At(secret, time.Now(), totp.Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []mfa.Factor{
		totp.Factor("dora", secret, []byte(code), nil),
		totp.Factor("dora", secret, []byte("000000"), nil),
		totp.Factor("dora", nil, []byte(code), nil), // not even "nobody enrolled"
	} {
		err := f.Verify(context.Background())
		if err == nil {
			t.Fatal("a factor with no Verifier accepted a code")
		}
		if errors.Is(err, mfa.ErrUnavailable) {
			t.Errorf("a missing Verifier reads as unavailable: %v", err)
		}
		if !strings.Contains(err.Error(), "Verifier") {
			t.Errorf("the error does not name what is missing: %q", err)
		}
	}
}

// knows is a factor for the test to put next to the code: something the person
// knows, answering as it is told to.
func knows(name string, err error) mfa.Factor { return knowledge{name, err} }

type knowledge struct {
	name string
	err  error
}

func (k knowledge) Name() string                 { return k.name }
func (k knowledge) Kind() mfa.Kind               { return mfa.Knowledge }
func (k knowledge) Verify(context.Context) error { return k.err }
