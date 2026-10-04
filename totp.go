// SPDX-License-Identifier: BSD-3-Clause

// Package totp is time-based one-time passwords: RFC 6238, and the factor a
// policy asks.
//
//	secret, _ := totp.ParseSecret("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP")
//	if err := totp.Verify(secret, code, totp.Options{}); err != nil { … }
//
// The six digits on a phone are HOTP (RFC 4226) with the counter replaced by
// the current half-minute. That is the whole idea, and everything else here is
// consequence:
//
//   - The code is valid for a WHOLE step -- thirty seconds by default -- so a
//     server that accepts one twice accepts a replay. RFC 6238 5.2 says the
//     verifier MUST NOT accept the same OTP twice, and [Verify] cannot do that
//     on its own: it holds nothing between calls. [Verifier] does, and a
//     server should use it.
//
//   - Clocks differ, so a window of one step either side is allowed by
//     default. Each step of window is a step of somebody else's guessing time;
//     it is a number to set deliberately, not to raise until the complaints
//     stop.
//
//   - The comparison is constant-time. A six-digit code has a million values
//     and a server that leaks how many leading digits were right has far
//     fewer.
//
// # The secret is the credential
//
// Anybody holding it produces every future code. It is not a hash of
// anything, it does not expire, and a directory that publishes it has
// published the second factor -- see [github.com/go-authn/directory], where
// that argument is made about the NT hash and applies here word for word.
package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"net/url"
	"strings"
	"time"
)

// Algorithm is the hash inside the HMAC.
//
// SHA1 is the default because it is what every authenticator app implements;
// the others are in RFC 6238 and are read by fewer things. This is a
// compatibility choice, not a security claim: HMAC-SHA1 is not weakened by the
// collision attacks that retired SHA1 for signatures.
type Algorithm int

// The hashes RFC 6238 names.
const (
	SHA1 Algorithm = iota
	SHA256
	SHA512
)

func (a Algorithm) String() string {
	switch a {
	case SHA1:
		return "SHA1"
	case SHA256:
		return "SHA256"
	case SHA512:
		return "SHA512"
	}
	return fmt.Sprintf("Algorithm(%d)", int(a))
}

func (a Algorithm) new() func() hash.Hash {
	switch a {
	case SHA256:
		return sha256.New
	case SHA512:
		return sha512.New
	}
	return sha1.New
}

// Options are the parameters an authenticator was enrolled with. The zero
// value is what every phone assumes: six digits, thirty seconds, SHA-1, and
// one step of tolerance either way.
type Options struct {
	// Digits is how many digits the code has. 0 means 6.
	Digits int
	// Period is how long one code lasts. 0 means 30 seconds.
	Period time.Duration
	// Algorithm is the hash inside the HMAC.
	Algorithm Algorithm
	// Window is how many steps either side of now are accepted, for clocks
	// that differ. 0 means 1 -- thirty seconds of slack in each direction.
	// Use [NoWindow] to accept only the current step. More than [MaxWindow]
	// is refused.
	Window int
	// Now overrides the clock, for tests and for a server that has a better
	// idea of the time than this process does.
	Now func() time.Time
}

// NoWindow accepts only the current step. It is a distinct value because 0
// means "the default", and a caller asking for no tolerance at all should not
// be given some.
const NoWindow = -1

// MaxWindow is the widest window accepted: ten steps either side, five
// minutes at the default period, is a clock wronger than any that should be
// trusted. ⛔ Without a ceiling, a window of 200,000 steps accepted half of
// all codes typed at random, and [math.MaxInt] never returned: the loop over
// the window overflowed before it could end.
const MaxWindow = 10

func (o Options) digits() int {
	if o.Digits == 0 {
		return 6
	}
	return o.Digits
}

func (o Options) period() time.Duration {
	if o.Period == 0 {
		return 30 * time.Second
	}
	return o.Period
}

func (o Options) window() int {
	switch {
	case o.Window == NoWindow:
		return 0
	case o.Window == 0:
		return 1
	}
	return o.Window
}

func (o Options) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

// check refuses parameters that cannot produce a code, rather than producing a
// wrong one.
func (o Options) check() error {
	if d := o.digits(); d < 6 || d > 10 {
		// Six is the floor RFC 4226 5.3 sets; ten is where a 31-bit
		// truncation stops adding digits that vary.
		return fmt.Errorf("totp: %d digits: RFC 4226 allows 6 to 10", d)
	}
	// RFC 6238 counts the period X in whole seconds, and Step divides by it
	// in seconds: anything under one second would be a division by zero, and
	// a fraction of a second would be silently dropped.
	if p := o.period(); p < time.Second || p%time.Second != 0 {
		return fmt.Errorf("totp: a period of %s: it must be a whole number of seconds", p)
	}
	if w := o.window(); w < 0 || w > MaxWindow {
		return fmt.Errorf("totp: a window of %d steps: 0 to %d are accepted", o.Window, MaxWindow)
	}
	return nil
}

// Step is the counter a time falls in: RFC 6238's T.
//
// For a period [Generate] and [Verify] refuse -- under one second -- it counts
// in seconds rather than dividing by zero; no code is ever made from that step.
func (o Options) Step(t time.Time) int64 {
	return t.Unix() / max(1, int64(o.period()/time.Second))
}

// Generate produces the code for one step. It is what an authenticator does,
// and what a test needs to produce a code a server should accept.
func Generate(secret []byte, step int64, o Options) (string, error) {
	if err := checkSecret(secret); err != nil {
		return "", err
	}
	if err := o.check(); err != nil {
		return "", err
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(step))
	mac := hmac.New(o.Algorithm.new(), secret)
	mac.Write(counter[:])
	sum := mac.Sum(nil)

	// Dynamic truncation, RFC 4226 5.3: the low nibble of the last byte says
	// where to read four bytes, and the top bit is cleared so the number is
	// positive in every language that has only signed integers.
	offset := sum[len(sum)-1] & 0x0f
	value := uint64(binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff)

	// ⛔ In 64 bits: 10^10 does not fit in 32, and a uint32 modulus wraps to
	// 1410065408 at ten digits, which gets about a third of all codes wrong.
	mod := uint64(1)
	for range o.digits() {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", o.digits(), value%mod), nil
}

// MinSecret is the shortest secret accepted, in bytes: RFC 4226 R6 says the
// shared secret MUST be at least 128 bits, and recommends 160.
const MinSecret = 16

// checkSecret refuses a secret too short to be one. The message gives the
// length and never the secret.
func checkSecret(secret []byte) error {
	if len(secret) == 0 {
		return fmt.Errorf("totp: no secret")
	}
	if len(secret) < MinSecret {
		return fmt.Errorf("totp: a secret of %d bits; RFC 4226 requires at least %d", 8*len(secret), 8*MinSecret)
	}
	return nil
}

// At produces the code for a time.
func At(secret []byte, t time.Time, o Options) (string, error) {
	if err := o.check(); err != nil {
		return "", err
	}
	return Generate(secret, o.Step(t), o)
}

// Verify checks a code against the current step and the window around it.
//
// ⛔ It does not, and cannot, refuse a code it has already accepted: nothing
// is kept between calls. A code is good for a whole period, so a server that
// only calls this accepts a replay within the same half-minute -- see
// [Verifier], which is the thing to use in a server.
func Verify(secret, code []byte, o Options) error {
	_, err := verifyStep(secret, code, o)
	return err
}

// verifyStep says WHICH step matched, which is what a replay guard needs.
func verifyStep(secret, code []byte, o Options) (int64, error) {
	if err := checkSecret(secret); err != nil {
		return 0, err
	}
	if err := o.check(); err != nil {
		return 0, err
	}
	if len(code) != o.digits() {
		// Said without quoting the code: it is a secret for the next half
		// minute, and an error message is the wrong place for one.
		return 0, fmt.Errorf("totp: a code of %d digits, and %d were given", o.digits(), len(code))
	}
	now := o.Step(o.now())
	// Every step in the window is tried, and the loop does not stop early:
	// returning as soon as one matches makes the time taken depend on WHICH
	// step it was, which is a small clock oracle for anybody watching.
	var matched int64
	var found int
	for i := -o.window(); i <= o.window(); i++ {
		want, err := Generate(secret, now+int64(i), o)
		if err != nil {
			return 0, err
		}
		if subtle.ConstantTimeCompare([]byte(want), code) == 1 {
			matched = now + int64(i)
			found++
		}
	}
	if found == 0 {
		return 0, ErrWrongCode
	}
	return matched, nil
}

// ErrWrongCode is a code that is not right for any step in the window. It is
// deliberately the same error for "wrong" and "too old": telling somebody
// which tells whoever is guessing which.
var ErrWrongCode = fmt.Errorf("totp: that code is not right")

// ParseSecret reads a secret in the base32 spelling authenticators use --
// upper case, spaces and padding optional, which is how people copy them.
func ParseSecret(s string) ([]byte, error) {
	clean := strings.ToUpper(strings.NewReplacer(" ", "", "-", "", "\t", "").Replace(strings.TrimSpace(s)))
	if clean == "" {
		return nil, fmt.Errorf("totp: no secret")
	}
	if pad := len(clean) % 8; pad != 0 {
		clean += strings.Repeat("=", 8-pad)
	}
	raw, err := base32.StdEncoding.DecodeString(clean)
	if err != nil {
		// Not quoting the input: it is the secret.
		return nil, fmt.Errorf("totp: the secret is not base32")
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("totp: no secret")
	}
	return raw, nil
}

// FormatSecret writes a secret the way an authenticator shows it.
func FormatSecret(secret []byte) string {
	return strings.TrimRight(base32.StdEncoding.EncodeToString(secret), "=")
}

// URI is the otpauth:// URL an authenticator reads from a QR code.
//
// The secret is IN it, which is what enrolment means -- so it is shown to the
// person enrolling and to nobody else, never logged, and never put in a link
// something else will follow.
func URI(issuer, account string, secret []byte, o Options) string {
	v := url.Values{}
	v.Set("secret", FormatSecret(secret))
	if issuer != "" {
		v.Set("issuer", issuer)
	}
	v.Set("algorithm", o.Algorithm.String())
	v.Set("digits", fmt.Sprint(o.digits()))
	v.Set("period", fmt.Sprint(int(o.period()/time.Second)))
	label := account
	if issuer != "" {
		label = issuer + ":" + account
	}
	u := url.URL{Scheme: "otpauth", Host: "totp", Path: "/" + label, RawQuery: v.Encode()}
	return u.String()
}
