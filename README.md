# totp

[![Go Reference](https://pkg.go.dev/badge/github.com/go-authn/totp.svg)](https://pkg.go.dev/github.com/go-authn/totp)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-0A6E96?style=flat-square)](LICENSE)
[![CI](https://github.com/go-authn/totp/actions/workflows/ci.yml/badge.svg)](https://github.com/go-authn/totp/actions/workflows/ci.yml)

**Time-based one-time passwords (RFC 6238), and the factor a policy asks.**
Pure Go, `CGO_ENABLED=0`, no dependencies but [go-authn/mfa](https://github.com/go-authn/mfa).

```go
secret, _ := totp.ParseSecret("JBSWY3DPEHPK3PXP")

r, err := mfa.Verify(ctx, mfa.Policy{Count: 2, DistinctKinds: true},
    password.Factor(given),                        // something they know
    totp.Factor("dora", secret, code, verifier),   // something they have
)
```

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

Every step in the window is tried and the loop does **not** stop early:
returning as soon as one matches makes the time taken depend on *which* step it
was. The comparison itself is constant-time — a six-digit code has a million
values, and a server that leaks how many leading digits were right has far
fewer.

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
- **200 random cases against pyotp** — secrets of 23 different lengths, 6 to 9
  digits, four periods, all three algorithms. The published vectors pin the
  arithmetic and leave the edges alone.
- Both judges were **sabotage-checked**: masking `0xffffffff` instead of
  `0x7fffffff` in the dynamic truncation fails 95 of 206 assertions, and
  reading the offset from the first byte instead of the last fails 196.

## Licence

BSD-3-Clause.
