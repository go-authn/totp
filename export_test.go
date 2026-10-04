package totp

// Remembered is how many credentials a Verifier holds, for the test that its
// memory is bounded.
func (v *Verifier) Remembered() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return len(v.creds)
}

// Aliases is how many names a Verifier holds.
func (v *Verifier) Aliases() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return len(v.names)
}
