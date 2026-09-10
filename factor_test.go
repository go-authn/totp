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
	f := totp.Factor("dora", nil, []byte("123456"), nil)
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

// Without a Verifier the factor still works -- it just cannot refuse a replay,
// which is the whole reason a server should pass one.
func TestAFactorWithoutAVerifier(t *testing.T) {
	secret := []byte("12345678901234567890")
	code, err := totp.At(secret, time.Now(), totp.Options{})
	if err != nil {
		t.Fatal(err)
	}
	f := totp.Factor("dora", secret, []byte(code), nil)
	if err := f.Verify(context.Background()); err != nil {
		t.Errorf("a right code was refused: %v", err)
	}
	if err := f.Verify(context.Background()); err != nil {
		t.Errorf("without a Verifier the second use should still pass: %v", err)
	}
	if err := totp.Factor("dora", secret, []byte("000000"), nil).Verify(context.Background()); err == nil {
		t.Error("a wrong code was accepted")
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
