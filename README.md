# totp

[![Go Reference](https://pkg.go.dev/badge/github.com/go-authn/totp.svg)](https://pkg.go.dev/github.com/go-authn/totp)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-0A6E96?style=flat-square)](LICENSE)
[![CI](https://github.com/go-authn/totp/actions/workflows/ci.yml/badge.svg)](https://github.com/go-authn/totp/actions/workflows/ci.yml)

**Time-based one-time passwords (RFC 6238), and the factor a policy asks.**
Pure Go, `CGO_ENABLED=0`, no dependencies but [go-authn/mfa](https://github.com/go-authn/mfa).

```go
secret, _ := totp.ParseSecret("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP")

// knows is yours: whatever checks the password, as an mfa.Factor whose Kind is
// mfa.Knowledge. This module provides the other half.
r, err := mfa.Verify(ctx, mfa.Policy{Count: 2, DistinctKinds: true},
    knows,                                         // something they know
    totp.Factor("dora", secret, code, verifier),   // something they have
)
```

The `*Verifier` is **required**. `Factor` with a nil one used to fall back to
the stateless `Verify` — no replay refusal, no throttle, no lockout: an audit
found the code after 236,089 wrong guesses in a quarter of a second, then
replayed it three times. Now the factor refuses every code, saying a Verifier
is missing; it is not reported as unavailable, so a policy cannot pass on the
other factors and hide the mistake.

Codes are six digits, every 30 seconds, HMAC-SHA1, one step either side,
unless `Options` says otherwise: `Digits`, `Period`, `Algorithm` (`SHA1`,
`SHA256`, `SHA512`) and `Window` (`NoWindow` for none: 0 means the default,
at most `MaxWindow` = 10). A `Verifier` carries its own `Options`, and
`FormatSecret` writes a secret the way `ParseSecret` reads it.

The six digits on a phone are HOTP (RFC 4226) with the counter replaced by the
current half-minute. That is the whole idea; everything below is consequence.

## A code is valid for a whole step, so a server must remember it

RFC 6238 §5.2: the verifier **MUST NOT** accept a second attempt of an OTP that
already succeeded. `Verify` cannot do that — it holds nothing between calls —
so a server uses a `Verifier`:

```go
v := &totp.Verifier{}
err := v.Verify("dora", secret, code)   // totp.ErrUsed the second time
```

Every step **up to and including** the last accepted one is refused, not just
the same one: a code from thirty seconds ago is still inside the default
window, and accepting it is the same replay with one more step of patience.

The memory is this process's. Two servers behind a load balancer each refuse
their own replays and neither knows about the other's — a deployment that needs
one answer needs a shared store, and `Verifier` is the seam to put it behind.

## The window is somebody's guessing time

One step either side by default, because clocks differ. `NoWindow` accepts only
the current step — a distinct constant, because `0` means *the default* and a
caller asking for no tolerance should not be handed some.

At most `MaxWindow` = 10 steps either side; a wider one is refused as a
parameter. Without that ceiling `Window: 200000` accepted half of all codes
typed at random, and `math.MaxInt` never returned — the loop over the window
overflowed before it could end.

Every step in the window is tried and the loop does **not** stop early:
returning as soon as one matches makes the time taken depend on *which* step it
was. The comparison itself is constant-time — a six-digit code has a million
values, and a server that leaks how many leading digits were right has far
fewer.

## Guessing is limited per secret

A six-digit code has a million values; without a limit, trying them in order
against one name got in after 292,211 guesses in 372 ms in an audit run.
RFC 4226 §7.3 says the server needs to detect and stop that, and that the
limit **MUST** hold across sessions and against parallel guessing. NIST SP
800-63B §5.2.2 says a verifier **SHALL** limit consecutive failed attempts on
one account to no more than 100. A `Verifier` does both, counting per
**credential** — per secret — and not per name:

| field | default | what it does |
| --- | --- | --- |
| `Throttle` | `DefaultThrottle` = 5 | after this many wrong codes in a row, the secret gets `ErrThrottled`… |
| `Pause` | `DefaultPause` = 15 min | …for this long; the code sent meanwhile is not looked at, so not even the right one passes |
| `Lockout` | `DefaultLockout` = 100 | after this many wrong codes in a row, however spread out, the secret gets `ErrLockedOut` until `Forget` |

RFC 4226 asks for a throttle "as low as possible, while still ensuring that
usability is not significantly impacted" and names no number; five is more
mistypes in a row than a person makes. The lockout is NIST's ceiling. With the
defaults a guesser gets 100 tries in about five hours and then none — with the
default window of three steps, a chance of 3 in 10,000 against six digits.
`errors.Is(err, totp.ErrThrottled)` is true for both refusals, so a caller that
checks only that refuses both.

Only a wrong code counts. A replay (`ErrUsed`), a code of the wrong length and
a refused secret or parameter are refused for their own reasons and do not
bring a pause nearer. An accepted code starts the count again. The whole check
is made under one lock, so guesses sent at the same moment are counted one by
one rather than each finding the count below the limit.

⛔ It was per name, and the name is whatever string the caller passes. A login
form that does not canonicalise gave `dora`, `Dora`, `DORA`… sixteen counters
for one secret: 1,600 wrong guesses where the lockout said 100. What a guesser
attacks is the secret, so the count follows it, under every spelling. A replay
is refused per secret too — the code accepted was the secret's, whatever name
it was typed under. The secret is held only as its SHA-256. The name is still
remembered beside the credential it last presented, refused or not, because
`Forget` takes a name: `Forget("dora")` unlocks the secret `dora` last tried.

The memory is bounded: a credential or a name nobody has tried for a day is
forgotten when the maps have doubled since they were last swept. A locked-out
credential is never forgotten that way — that would be an unlock nobody asked for. And the limit is a lockout
someone else can trigger: whoever knows a name can lock it. That is the
trade-off both documents accept; `Forget` is the way back, and it belongs to
whoever can tell the person from somebody guessing.

## Parameters that cannot be right are refused

- **The secret is at least 128 bits** (`MinSecret` = 16 bytes), RFC 4226 R6, in
  `Generate`, `At`, `Verify` and `Verifier.Verify`. `ParseSecret` still reads a
  shorter one — it is a parser — and nothing will make a code from it.
- **The period is a whole number of seconds**, at least one: RFC 6238 counts it
  in seconds, and half a second used to divide by zero.
- **6 to 10 digits**, RFC 4226 §5.3, with the reduction done in 64 bits: 10^10
  does not fit in 32.

## The secret is the credential

Anybody holding it produces every future code. It is not a hash of anything, it
does not expire, and a directory that publishes it has published the second
factor — the same argument [go-authn/directory](https://github.com/go-authn/directory)
makes about the NT hash, word for word.

So: no error message here quotes a code or a secret, and `URI` — the
`otpauth://` string an authenticator reads from a QR code — carries the secret
by construction and is shown to the person enrolling and to nobody else.

## Verified against things that are not this package

- **RFC 6238 Appendix B**, all six times and all three algorithms. The seeds
  are the ASCII digits repeated to the hash's key length (20, 32, 64 bytes) —
  the RFC's table is famously ambiguous about that, so the reading was
  **measured**: an independent implementation produces the RFC's published
  codes from it.
- **RFC 4226 Appendix D**, counters 0 to 9: the six-digit codes, and the
  "truncated" column, which is the ten-digit code because 2^31 < 10^10.
- **200 random cases against pyotp** — secrets of 23 different lengths from
  16 bytes, 6 to 10 digits, four periods, all three algorithms. The published
  vectors pin the arithmetic and leave the edges alone.
- **Every digit count, 1000 steps per algorithm**, against RFC 4226 §5.3
  computed again in the test with the reduction in arbitrary precision.
- Both judges were **sabotage-checked**: masking `0xffffffff` instead of
  `0x7fffffff` in the dynamic truncation fails 95 of 206 assertions, and
  reading the offset from the first byte instead of the last fails 196.

## Licence

BSD-3-Clause.
