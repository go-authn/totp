package totp_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-authn/totp"
)

// RFC 6238 Appendix B, which is the whole chain judged at once: HMAC, the
// dynamic truncation, the digits, and the time step.
//
// The seeds are the ASCII string "12345678901234567890" repeated to the
// hash's block-key length -- 20 bytes for SHA-1, 32 for SHA-256, 64 for
// SHA-512. That reading is the one an independent implementation (pyotp)
// produces the RFC's published codes from; the RFC's own table is famously
// ambiguous about it, so it was measured rather than remembered.
func TestRFC6238(t *testing.T) {
	sha1Key := []byte("12345678901234567890")
	sha256Key := []byte("12345678901234567890123456789012")
	sha512Key := []byte("1234567890123456789012345678901234567890123456789012345678901234")
	for _, tc := range []struct {
		unix                 int64
		sha1, sha256, sha512 string
	}{
		{59, "94287082", "46119246", "90693936"},
		{1111111109, "07081804", "68084774", "25091201"},
		{1111111111, "14050471", "67062674", "99943326"},
		{1234567890, "89005924", "91819424", "93441116"},
		{2000000000, "69279037", "90698825", "38618901"},
		{20000000000, "65353130", "77737706", "47863826"},
	} {
		when := time.Unix(tc.unix, 0).UTC()
		for _, k := range []struct {
			alg    totp.Algorithm
			secret []byte
			want   string
		}{
			{totp.SHA1, sha1Key, tc.sha1},
			{totp.SHA256, sha256Key, tc.sha256},
			{totp.SHA512, sha512Key, tc.sha512},
		} {
			got, err := totp.At(k.secret, when, totp.Options{Digits: 8, Algorithm: k.alg})
			if err != nil {
				t.Fatalf("T=%d %s: %v", tc.unix, k.alg, err)
			}
			if got != k.want {
				t.Errorf("T=%d %s = %s, want %s", tc.unix, k.alg, got, k.want)
			}
		}
	}
}

// A code is right for its own step and wrong outside the window.
func TestTheWindowIsTheWindow(t *testing.T) {
	secret := []byte("12345678901234567890")
	at := time.Unix(1111111109, 0)
	o := func(window int) totp.Options {
		return totp.Options{Window: window, Now: func() time.Time { return at }}
	}
	code, err := totp.At(secret, at, o(0))
	if err != nil {
		t.Fatal(err)
	}
	// The default window is one step either side, so the codes for the
	// neighbouring steps are accepted too -- clocks differ.
	for _, step := range []int64{-1, 0, 1} {
		near, err := totp.Generate(secret, totp.Options{}.Step(at)+step, o(0))
		if err != nil {
			t.Fatal(err)
		}
		if err := totp.Verify(secret, []byte(near), o(0)); err != nil {
			t.Errorf("the code %d step(s) away was refused: %v", step, err)
		}
	}
	// Two steps away is not.
	far, _ := totp.Generate(secret, totp.Options{}.Step(at)+2, o(0))
	if err := totp.Verify(secret, []byte(far), o(0)); !errors.Is(err, totp.ErrWrongCode) {
		t.Errorf("a code two steps away gave %v", err)
	}
	// And with no window at all, only the current step is right.
	prev, _ := totp.Generate(secret, totp.Options{}.Step(at)-1, o(totp.NoWindow))
	if err := totp.Verify(secret, []byte(prev), o(totp.NoWindow)); !errors.Is(err, totp.ErrWrongCode) {
		t.Errorf("NoWindow accepted the previous step: %v", err)
	}
	if err := totp.Verify(secret, []byte(code), o(totp.NoWindow)); err != nil {
		t.Errorf("NoWindow refused the current step: %v", err)
	}
}

// ⛔ A code is valid for a whole step, so a server that accepts one twice
// accepts a replay (RFC 6238 §5.2). A Verifier refuses the second attempt.
func TestACodeIsUsedOnce(t *testing.T) {
	secret := []byte("12345678901234567890")
	at := time.Unix(1111111109, 0)
	v := &totp.Verifier{Options: totp.Options{Now: func() time.Time { return at }}}
	code, err := totp.At(secret, at, v.Options)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Verify("dora", secret, []byte(code)); err != nil {
		t.Fatalf("the first use was refused: %v", err)
	}
	if err := v.Verify("dora", secret, []byte(code)); !errors.Is(err, totp.ErrUsed) {
		t.Errorf("the second use gave %v, want ErrUsed", err)
	}
	// Somebody ELSE's use of their own code is not a replay of this one: the
	// memory is per person.
	if err := v.Verify("eli", secret, []byte(code)); err != nil {
		t.Errorf("eli's first use was refused because dora had used hers: %v", err)
	}
	// ⛔ And the older code still inside the window is refused too -- it would
	// otherwise be the same replay with one more step of patience.
	older, _ := totp.Generate(secret, v.Options.Step(at)-1, v.Options)
	if err := v.Verify("dora", secret, []byte(older)); !errors.Is(err, totp.ErrUsed) {
		t.Errorf("a code from the previous step gave %v, want ErrUsed", err)
	}
	// The next step is a new code and is accepted.
	next, _ := totp.Generate(secret, v.Options.Step(at)+1, v.Options)
	if err := v.Verify("dora", secret, []byte(next)); err != nil {
		t.Errorf("the next step's code was refused: %v", err)
	}
	// Forgetting somebody starts them again.
	v.Forget("dora")
	if err := v.Verify("dora", secret, []byte(code)); err != nil {
		t.Errorf("after Forget, the code was still refused: %v", err)
	}
}

// A wrong code is wrong, and says so without saying anything else.
func TestAWrongCodeSaysNothingUseful(t *testing.T) {
	secret := []byte("12345678901234567890")
	at := time.Unix(1111111109, 0)
	o := totp.Options{Now: func() time.Time { return at }}
	code, _ := totp.At(secret, at, o)

	err := totp.Verify(secret, []byte("000000"), o)
	if !errors.Is(err, totp.ErrWrongCode) {
		t.Errorf("a wrong code gave %v", err)
	}
	// The message never quotes the code: it is a secret for the next half
	// minute, and an error message is the wrong place for one.
	if strings.Contains(err.Error(), "000000") {
		t.Errorf("the refusal quotes the code: %q", err)
	}
	if err := totp.Verify(secret, []byte("12345"), o); err == nil {
		t.Error("a code of the wrong length was accepted")
	} else if strings.Contains(err.Error(), "12345") {
		t.Errorf("the refusal quotes the code: %q", err)
	}
	// A different secret gives a different code, which is the point.
	other, _ := totp.At([]byte("09876543210987654321"), at, o)
	if other == code {
		t.Error("two secrets gave the same code")
	}
	if err := totp.Verify(secret, []byte(other), o); !errors.Is(err, totp.ErrWrongCode) {
		t.Errorf("another secret's code gave %v", err)
	}
}

// Secrets are read the way people copy them: spaces, lower case, no padding.
func TestSecretsAreReadAsPeopleCopyThem(t *testing.T) {
	want, err := totp.ParseSecret("JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatal(err)
	}
	for _, spelling := range []string{
		"jbswy3dpehpk3pxp",
		"JBSW Y3DP EHPK 3PXP",
		"JBSW-Y3DP-EHPK-3PXP",
		"  JBSWY3DPEHPK3PXP  ",
	} {
		got, err := totp.ParseSecret(spelling)
		if err != nil {
			t.Errorf("%q: %v", spelling, err)
			continue
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%q read as something else", spelling)
		}
	}
	// And what is not base32 is refused without being quoted back.
	if _, err := totp.ParseSecret("not base 32 at all!"); err == nil {
		t.Error("a secret that is not base32 was accepted")
	} else if strings.Contains(err.Error(), "not base 32 at all") {
		t.Errorf("the refusal quotes the secret: %q", err)
	}
	if _, err := totp.ParseSecret("   "); err == nil {
		t.Error("an empty secret was accepted")
	}
	// FormatSecret is the way back, and round-trips.
	if again, err := totp.ParseSecret(totp.FormatSecret(want)); err != nil || !bytes.Equal(again, want) {
		t.Errorf("FormatSecret did not round-trip: %v", err)
	}
}

// Parameters that cannot produce a code are refused rather than producing a
// wrong one.
func TestParametersThatCannotWork(t *testing.T) {
	secret := []byte("12345678901234567890")
	for _, tc := range []struct {
		name string
		o    totp.Options
	}{
		{"five digits", totp.Options{Digits: 5}},
		{"eleven digits", totp.Options{Digits: 11}},
		{"a period of zero minus", totp.Options{Period: -time.Second}},
	} {
		if _, err := totp.At(secret, time.Now(), tc.o); err == nil {
			t.Errorf("%s was accepted", tc.name)
		}
		if err := totp.Verify(secret, []byte("123456"), tc.o); err == nil {
			t.Errorf("%s was accepted by Verify", tc.name)
		}
	}
	if _, err := totp.At(nil, time.Now(), totp.Options{}); err == nil {
		t.Error("a code was produced with no secret")
	}
	if err := totp.Verify(nil, []byte("123456"), totp.Options{}); err == nil {
		t.Error("a code was verified with no secret")
	}
}

// The enrolment URI is what an authenticator reads, and it carries the secret.
func TestTheEnrolmentURI(t *testing.T) {
	secret, _ := totp.ParseSecret("JBSWY3DPEHPK3PXP")
	uri := totp.URI("Example", "dora@example.org", secret, totp.Options{})
	for _, want := range []string{
		"otpauth://totp/Example:dora@example.org",
		"secret=JBSWY3DPEHPK3PXP",
		"issuer=Example",
		"algorithm=SHA1",
		"digits=6",
		"period=30",
	} {
		if !strings.Contains(uri, want) {
			t.Errorf("the URI does not carry %q:\n%s", want, uri)
		}
	}
	// Without an issuer the label is just the account, which is what
	// authenticators show.
	if uri := totp.URI("", "dora", secret, totp.Options{Digits: 8, Period: time.Minute, Algorithm: totp.SHA256}); !strings.Contains(uri, "otpauth://totp/dora") ||
		!strings.Contains(uri, "digits=8") || !strings.Contains(uri, "period=60") || !strings.Contains(uri, "algorithm=SHA256") {
		t.Errorf("the URI reads %s", uri)
	}
}

// The names are the ones RFC 6238 uses, because a configuration file will
// spell them and a person will read them back.
func TestAlgorithmsAreNamed(t *testing.T) {
	for alg, want := range map[totp.Algorithm]string{
		totp.SHA1: "SHA1", totp.SHA256: "SHA256", totp.SHA512: "SHA512", totp.Algorithm(9): "Algorithm(9)",
	} {
		if got := alg.String(); got != want {
			t.Errorf("%d = %q, want %q", int(alg), got, want)
		}
	}
	// An algorithm nobody has falls back to the one everything implements,
	// rather than producing nothing: Generate has already refused everything
	// it can refuse, and a code is better than a panic.
	if _, err := totp.At([]byte("12345678901234567890"), time.Now(), totp.Options{Algorithm: totp.Algorithm(9)}); err != nil {
		t.Errorf("an unknown algorithm gave %v", err)
	}
}

// The remaining corners, which are the ones a caller reaches by accident.
func TestCorners(t *testing.T) {
	secret := []byte("12345678901234567890")
	at := time.Unix(1111111109, 0)

	// A window given explicitly is used as given.
	o := totp.Options{Window: 3, Now: func() time.Time { return at }}
	three, _ := totp.Generate(secret, o.Step(at)-3, o)
	if err := totp.Verify(secret, []byte(three), o); err != nil {
		t.Errorf("a window of 3 refused a code 3 steps away: %v", err)
	}
	four, _ := totp.Generate(secret, o.Step(at)-4, o)
	if err := totp.Verify(secret, []byte(four), o); !errors.Is(err, totp.ErrWrongCode) {
		t.Errorf("a window of 3 accepted a code 4 steps away: %v", err)
	}
	// A negative window is refused rather than read as "none".
	if err := totp.Verify(secret, []byte("123456"), totp.Options{Window: -7}); err == nil {
		t.Error("a window of -7 was accepted")
	}

	// A secret that decodes to nothing is no secret.
	if _, err := totp.ParseSecret("========"); err == nil {
		t.Error("a secret of only padding was accepted")
	}

	// A Verifier passes its parameter errors through rather than remembering
	// a step that never matched.
	v := &totp.Verifier{Options: totp.Options{Digits: 99}}
	if err := v.Verify("dora", secret, []byte("123456")); err == nil {
		t.Error("a Verifier accepted parameters that cannot produce a code")
	}
	// And Forget on somebody it never saw is not a panic.
	v.Forget("nobody")

	// Ten digits is the ceiling RFC 4226 allows, and it works.
	long, err := totp.At(secret, at, totp.Options{Digits: 10})
	if err != nil || len(long) != 10 {
		t.Errorf("ten digits gave %q, %v", long, err)
	}
}
