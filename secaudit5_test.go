// SPDX-License-Identifier: BSD-3-Clause

package totp

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
	"time"
)

// Security audit 2026-11-21, proof F4. The Verifier's doc says a stream of
// names "cannot grow it for ever". The names map is swept only when a NEW
// credential is remembered; every attempt on a KNOWN credential -- locked out
// included, where the code is not even looked at -- writes v.names[name]
// first. One enrolled secret reached under many spellings of its name (the
// case the per-credential count was introduced for) grows the map without
// bound, at no cost to the sender, and nothing ever sweeps it.
func TestSecAudit5NamesGrowWithoutBoundOnOneCredential(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	v := &Verifier{Options: Options{Now: func() time.Time { return now }}, Lockout: 1}
	secret := bytes.Repeat([]byte{7}, 20)
	if err := v.Verify("dora", secret, []byte("000000")); !errors.Is(err, ErrWrongCode) && err != nil {
		t.Fatal(err)
	}
	const n = 50_000
	for i := range n {
		now = now.Add(48 * time.Hour) // every earlier name is long idle
		if err := v.Verify(fmt.Sprintf("dora+%d", i), secret, []byte("000000")); !errors.Is(err, ErrLockedOut) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	if got := len(v.names); got > 2048 {
		t.Errorf("%d names remembered for ONE locked-out credential, each idle for days: the map is never swept", got)
	}
}
