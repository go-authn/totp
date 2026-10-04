package totp_test

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/go-authn/totp"
)

// RFC 4226 Appendix D: HOTP for the counters 0 to 9, which here are steps.
//
// The table's "truncated" column is the 31-bit number before the reduction
// modulo 10^Digit. 2^31 is smaller than 10^10, so a ten-digit code IS that
// number, padded with zeros: the RFC publishes the ten-digit codes without
// saying so. A modulus held in 32 bits wraps at ten digits (10^10 mod 2^32 is
// 1410065408) and gets every counter whose truncated value is above that
// wrong -- counters 3, 4 and 6 here.
func TestRFC4226AppendixD(t *testing.T) {
	secret := []byte("12345678901234567890")
	for counter, want := range []struct{ ten, six string }{
		{"1284755224", "755224"},
		{"1094287082", "287082"},
		{"0137359152", "359152"},
		{"1726969429", "969429"},
		{"1640338314", "338314"},
		{"0868254676", "254676"},
		{"1918287922", "287922"},
		{"0082162583", "162583"},
		{"0673399871", "399871"},
		{"0645520489", "520489"},
	} {
		six, err := totp.Generate(secret, int64(counter), totp.Options{})
		if err != nil {
			t.Fatal(err)
		}
		if six != want.six {
			t.Errorf("counter %d, 6 digits = %s, RFC 4226 says %s", counter, six, want.six)
		}
		ten, err := totp.Generate(secret, int64(counter), totp.Options{Digits: 10})
		if err != nil {
			t.Fatal(err)
		}
		if ten != want.ten {
			t.Errorf("counter %d, 10 digits = %s, RFC 4226 says %s", counter, ten, want.ten)
		}
	}
}

// Every digit count, every algorithm, a thousand steps, against RFC 4226 5.3
// computed here a second time with the reduction done in arbitrary precision,
// so that no fixed-width integer is shared between the judge and the judged.
func TestEveryDigitCountAgainstASecondComputation(t *testing.T) {
	keys := map[totp.Algorithm][]byte{
		totp.SHA1:   []byte("12345678901234567890"),
		totp.SHA256: []byte("12345678901234567890123456789012"),
		totp.SHA512: []byte("1234567890123456789012345678901234567890123456789012345678901234"),
	}
	hashes := map[totp.Algorithm]func() hash.Hash{totp.SHA1: sha1.New, totp.SHA256: sha256.New, totp.SHA512: sha512.New}
	for alg, key := range keys {
		for digits := 6; digits <= 10; digits++ {
			diff := 0
			for step := int64(0); step < 1000; step++ {
				got, err := totp.Generate(key, step*7919, totp.Options{Digits: digits, Algorithm: alg})
				if err != nil {
					t.Fatal(err)
				}
				if want := hotp(hashes[alg], key, step*7919, digits); got != want {
					if diff < 3 {
						t.Errorf("%s, %d digits, step %d = %s, want %s", alg, digits, step*7919, got, want)
					}
					diff++
				}
			}
			if diff > 0 {
				t.Errorf("%s, %d digits: %d of 1000 steps differ", alg, digits, diff)
			}
		}
	}
}

func hotp(h func() hash.Hash, key []byte, counter int64, digits int) string {
	var c [8]byte
	binary.BigEndian.PutUint64(c[:], uint64(counter))
	m := hmac.New(h, key)
	m.Write(c[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := new(big.Int).SetBytes(sum[off : off+4])
	v.And(v, big.NewInt(0x7fffffff))
	v.Mod(v, new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(digits)), nil))
	return fmt.Sprintf("%0*s", digits, v.String())
}

// A period is counted in whole seconds -- RFC 6238's X, and the unit Step
// divides by. Half a second used to pass the check and then divide by zero.
func TestAPeriodIsWholeSeconds(t *testing.T) {
	secret := []byte("12345678901234567890")
	for _, p := range []time.Duration{time.Nanosecond, 500 * time.Millisecond, 1500 * time.Millisecond, 30*time.Second + time.Millisecond} {
		o := totp.Options{Period: p}
		if _, err := totp.At(secret, time.Now(), o); err == nil {
			t.Errorf("a period of %s was accepted by At", p)
		}
		if err := totp.Verify(secret, []byte("123456"), o); err == nil || errors.Is(err, totp.ErrWrongCode) {
			t.Errorf("a period of %s gave %v from Verify, want a refusal of the period", p, err)
		}
		v := &totp.Verifier{Options: o}
		if err := v.Verify("dora", secret, []byte("123456")); err == nil || errors.Is(err, totp.ErrWrongCode) {
			t.Errorf("a period of %s gave %v from a Verifier", p, err)
		}
	}
	// One second is the smallest period there is, and it works.
	if _, err := totp.At(secret, time.Now(), totp.Options{Period: time.Second}); err != nil {
		t.Errorf("a period of one second was refused: %v", err)
	}
}

// RFC 4226 R6: the shared secret MUST be at least 128 bits. Fifteen bytes is
// refused everywhere a code is produced or checked; sixteen is accepted.
func TestASecretIsAtLeast128Bits(t *testing.T) {
	at := time.Unix(1111111109, 0)
	o := totp.Options{Now: func() time.Time { return at }}
	for _, n := range []int{1, 10, 15} {
		short := []byte("1234567890123456789012345678901234567890")[:n]
		if _, err := totp.At(short, at, o); err == nil {
			t.Errorf("a code was produced from a %d-byte secret", n)
		}
		if _, err := totp.Generate(short, 1, o); err == nil {
			t.Errorf("Generate accepted a %d-byte secret", n)
		}
		code := codeFor(t, short, at)
		if err := totp.Verify(short, []byte(code), o); err == nil {
			t.Errorf("Verify accepted the right code for a %d-byte secret", n)
		}
		v := &totp.Verifier{Options: o}
		if err := v.Verify("dora", short, []byte(code)); err == nil {
			t.Errorf("a Verifier accepted the right code for a %d-byte secret", n)
		}
	}
	// The audit's example: base32 "AE" is one byte, which ParseSecret still
	// reads -- it is a parser -- and nothing will make a code from.
	s, err := totp.ParseSecret("AE")
	if err != nil {
		t.Fatalf("ParseSecret(\"AE\"): %v", err)
	}
	if _, err := totp.At(s, at, o); err == nil {
		t.Error("a code was produced from an 8-bit secret")
	}
	sixteen := []byte("1234567890123456")
	code, err := totp.At(sixteen, at, o)
	if err != nil {
		t.Fatalf("a 16-byte secret was refused: %v", err)
	}
	if err := totp.Verify(sixteen, []byte(code), o); err != nil {
		t.Errorf("the right code for a 16-byte secret was refused: %v", err)
	}
}

// codeFor computes a code without the package, for a secret it refuses.
func codeFor(t *testing.T, secret []byte, at time.Time) string {
	t.Helper()
	return hotp(sha1.New, secret, at.Unix()/30, 6)
}

// wrongAt finds a code that is not right for any step in the default window.
func wrongAt(t *testing.T, secret []byte, at time.Time) []byte {
	t.Helper()
	o := totp.Options{Now: func() time.Time { return at }}
	for i := 0; i < 1000; i++ {
		c := []byte(fmt.Sprintf("%06d", i))
		if errors.Is(totp.Verify(secret, c, o), totp.ErrWrongCode) {
			return c
		}
	}
	t.Fatal("no wrong code among the first thousand")
	return nil
}

// clock is a time a test moves by hand. It is read under a lock because the
// concurrency test reads it from many goroutines.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// ⛔ RFC 4226 7.3: a six-digit code has a million values, so the server MUST
// stop somebody trying them. The audit's proof of concept tried them in order
// against one name and was let in after 292,211 guesses in 372 ms. Here the
// same million are tried: five are checked, every other one is refused
// without being looked at, and none is accepted.
func TestBruteForceIsStopped(t *testing.T) {
	secret, err := totp.ParseSecret("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatal(err)
	}
	fixed := time.Unix(1_800_000_000, 0)
	v := &totp.Verifier{Options: totp.Options{Now: func() time.Time { return fixed }}}
	checked := 0
	for i := 0; i < 1_000_000; i++ {
		err := v.Verify("dora", secret, []byte(fmt.Sprintf("%06d", i)))
		switch {
		case err == nil:
			t.Fatalf("guess #%d was accepted", i+1)
		case errors.Is(err, totp.ErrThrottled):
		case errors.Is(err, totp.ErrWrongCode):
			checked++
		default:
			t.Fatalf("guess #%d: %v", i+1, err)
		}
	}
	if checked != totp.DefaultThrottle {
		t.Errorf("%d guesses were checked, want %d", checked, totp.DefaultThrottle)
	}
}

// The pause: after DefaultThrottle wrong codes in a row a name is refused --
// even the right code, which would otherwise be an oracle -- until
// DefaultPause has passed. Refused attempts are not counted and do not
// extend it. Other names are not affected.
func TestAPauseAfterWrongCodes(t *testing.T) {
	secret := []byte("12345678901234567890")
	c := &clock{now: time.Unix(1111111109, 0)}
	v := &totp.Verifier{Options: totp.Options{Now: c.Now}}
	for i := 0; i < totp.DefaultThrottle; i++ {
		if err := v.Verify("dora", secret, wrongAt(t, secret, c.Now())); !errors.Is(err, totp.ErrWrongCode) {
			t.Fatalf("wrong code #%d gave %v", i+1, err)
		}
	}
	right, _ := totp.At(secret, c.Now(), v.Options)
	err := v.Verify("dora", secret, []byte(right))
	if !errors.Is(err, totp.ErrThrottled) {
		t.Fatalf("the right code during the pause gave %v, want ErrThrottled", err)
	}
	if errors.Is(err, totp.ErrLockedOut) {
		t.Errorf("a pause reads as a lockout: %v", err)
	}
	if err := v.Verify("eli", secret, []byte(right)); err != nil {
		t.Errorf("eli was refused because dora was paused: %v", err)
	}
	// Refusals during the pause neither count nor extend it.
	for i := 0; i < 50; i++ {
		_ = v.Verify("dora", secret, wrongAt(t, secret, c.Now()))
	}
	c.Add(totp.DefaultPause - time.Second)
	right, _ = totp.At(secret, c.Now(), v.Options)
	if err := v.Verify("dora", secret, []byte(right)); !errors.Is(err, totp.ErrThrottled) {
		t.Errorf("a second before the pause ends gave %v", err)
	}
	c.Add(time.Second)
	if err := v.Verify("dora", secret, []byte(right)); err != nil {
		t.Errorf("the right code after the pause was refused: %v", err)
	}
	// And the success started the count again from nothing.
	for i := 0; i < totp.DefaultThrottle-1; i++ {
		if err := v.Verify("dora", secret, wrongAt(t, secret, c.Now())); !errors.Is(err, totp.ErrWrongCode) {
			t.Fatalf("after a success, wrong code #%d gave %v", i+1, err)
		}
	}
	c.Add(30 * time.Second)
	right, _ = totp.At(secret, c.Now(), v.Options)
	if err := v.Verify("dora", secret, []byte(right)); err != nil {
		t.Errorf("one wrong code short of the throttle, the right one was refused: %v", err)
	}
}

// Only a wrong code is a guess. A replay of a code that was right, a code of
// the wrong length, and parameters that cannot work are refused for their own
// reasons and do not bring a pause nearer.
func TestOnlyWrongCodesCount(t *testing.T) {
	secret := []byte("12345678901234567890")
	c := &clock{now: time.Unix(1111111109, 0)}
	v := &totp.Verifier{Options: totp.Options{Now: c.Now}}
	right, _ := totp.At(secret, c.Now(), v.Options)
	if err := v.Verify("dora", secret, []byte(right)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3*totp.DefaultThrottle; i++ {
		if err := v.Verify("dora", secret, []byte(right)); !errors.Is(err, totp.ErrUsed) {
			t.Fatalf("replay #%d gave %v", i+1, err)
		}
		if err := v.Verify("dora", secret, []byte("12345")); err == nil || errors.Is(err, totp.ErrThrottled) {
			t.Fatalf("a short code #%d gave %v", i+1, err)
		}
		if err := v.Verify("dora", []byte("short"), []byte(right)); err == nil || errors.Is(err, totp.ErrThrottled) {
			t.Fatalf("a short secret #%d gave %v", i+1, err)
		}
	}
	c.Add(30 * time.Second)
	right, _ = totp.At(secret, c.Now(), v.Options)
	if err := v.Verify("dora", secret, []byte(right)); err != nil {
		t.Errorf("after refusals that were not guesses, the right code was refused: %v", err)
	}
}

// ⛔ NIST SP 800-63B 5.2.2: the verifier SHALL limit consecutive failed
// attempts on one account to no more than 100. The pause alone does not: it
// slows guessing down and lets it go on forever. After DefaultLockout wrong
// codes in a row, however spread out, the name is refused until Forget.
func TestALockoutAfterAHundred(t *testing.T) {
	secret := []byte("12345678901234567890")
	c := &clock{now: time.Unix(1111111109, 0)}
	v := &totp.Verifier{Options: totp.Options{Now: c.Now}}
	for i := 0; i < totp.DefaultLockout; i++ {
		if i > 0 && i%totp.DefaultThrottle == 0 {
			c.Add(totp.DefaultPause)
		}
		if err := v.Verify("dora", secret, wrongAt(t, secret, c.Now())); !errors.Is(err, totp.ErrWrongCode) {
			t.Fatalf("wrong code #%d gave %v", i+1, err)
		}
	}
	c.Add(30 * 24 * time.Hour)
	right, _ := totp.At(secret, c.Now(), v.Options)
	err := v.Verify("dora", secret, []byte(right))
	if !errors.Is(err, totp.ErrLockedOut) || !errors.Is(err, totp.ErrThrottled) {
		t.Fatalf("a month later, the right code gave %v, want ErrLockedOut (which is also ErrThrottled)", err)
	}
	v.Forget("dora")
	if err := v.Verify("dora", secret, []byte(right)); err != nil {
		t.Errorf("after Forget, the right code was refused: %v", err)
	}
}

// The limits are the caller's to set.
func TestTheLimitsAreSettable(t *testing.T) {
	secret := []byte("12345678901234567890")
	c := &clock{now: time.Unix(1111111109, 0)}
	v := &totp.Verifier{Options: totp.Options{Now: c.Now}, Throttle: 2, Pause: time.Minute, Lockout: 4}
	wrong := func() error { return v.Verify("dora", secret, wrongAt(t, secret, c.Now())) }
	for range 2 {
		if err := wrong(); !errors.Is(err, totp.ErrWrongCode) {
			t.Fatal(err)
		}
	}
	if err := wrong(); !errors.Is(err, totp.ErrThrottled) {
		t.Fatalf("a throttle of 2 let a third through: %v", err)
	}
	c.Add(time.Minute)
	for range 2 {
		if err := wrong(); !errors.Is(err, totp.ErrWrongCode) {
			t.Fatal(err)
		}
	}
	c.Add(time.Hour)
	if err := wrong(); !errors.Is(err, totp.ErrLockedOut) {
		t.Fatalf("a lockout of 4 let a fifth through: %v", err)
	}
}

// ⛔ RFC 4226 7.3: the limit MUST hold across sessions "to prevent attacks
// based on multiple parallel guessing techniques". Guesses sent all at once
// must not each find the count below the limit before any of them is counted.
func TestParallelGuessesAreCountedToo(t *testing.T) {
	secret := []byte("12345678901234567890")
	at := time.Unix(1111111109, 0)
	v := &totp.Verifier{Options: totp.Options{Now: func() time.Time { return at }}}
	wrong := wrongAt(t, secret, at)
	var mu sync.Mutex
	checked := 0
	var wg sync.WaitGroup
	for range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if errors.Is(v.Verify("dora", secret, wrong), totp.ErrWrongCode) {
				mu.Lock()
				checked++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if checked != totp.DefaultThrottle {
		t.Errorf("64 parallel guesses: %d were checked, want %d", checked, totp.DefaultThrottle)
	}
}

// The memory is bounded: a name nobody has tried for a day is forgotten, so a
// stream of names does not grow it for ever. A name that is locked out is not
// forgotten -- that would be an unlock nobody asked for.
func TestIdleNamesAreForgotten(t *testing.T) {
	secret := []byte("12345678901234567890")
	c := &clock{now: time.Unix(1111111109, 0)}
	v := &totp.Verifier{Options: totp.Options{Now: c.Now}, Lockout: 1}
	wrong := wrongAt(t, secret, c.Now())
	if err := v.Verify("locked", secret, wrong); !errors.Is(err, totp.ErrWrongCode) {
		t.Fatal(err)
	}
	// Names that were let in: the memory of their last step is what refuses a
	// replay, and once that step is a day old it refuses nothing.
	right, _ := totp.At(secret, c.Now(), v.Options)
	for i := range 5000 {
		if err := v.Verify(fmt.Sprintf("old-%d", i), secret, []byte(right)); err != nil {
			t.Fatal(err)
		}
	}
	if n := v.Remembered(); n < 5000 {
		t.Fatalf("%d names remembered right after 5001 were tried", n)
	}
	c.Add(25 * time.Hour)
	right, _ = totp.At(secret, c.Now(), v.Options)
	for i := range 5000 {
		if err := v.Verify(fmt.Sprintf("new-%d", i), secret, []byte(right)); err != nil {
			t.Fatal(err)
		}
	}
	if n := v.Remembered(); n != 5001 {
		t.Errorf("%d names remembered, want the 5000 recent ones and the locked one", n)
	}
	if err := v.Verify("locked", secret, []byte(right)); !errors.Is(err, totp.ErrLockedOut) {
		t.Errorf("the locked name, a day later, gave %v", err)
	}
}
