package totp_test

import (
	"crypto/rand"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/go-authn/totp"
)

// Two hundred codes, against an implementation nobody here wrote.
//
// RFC 6238's own vectors (next door) are six times, one secret per algorithm
// and eight digits. They pin the arithmetic and leave the edges untested:
// the shortest secret accepted (16 bytes, RFC 4226 R6) and secrets whose
// length is not a multiple of anything, six, seven, nine and ten digits --
// ten being where a 32-bit modulus wraps -- periods that are not thirty
// seconds, times far from the ones in the table. pyotp is a widely used
// Python implementation, and it agrees with the RFC's published table before
// this package is asked anything -- which is what makes it usable as a judge
// rather than a second opinion.
//
// It skips where pyotp is not installed. The CI lane installs it.
func TestAgainstAnIndependentImplementation(t *testing.T) {
	python := needPyOTP(t)

	type want struct {
		Secret string `json:"secret"`
		Unix   int64  `json:"unix"`
		Digits int    `json:"digits"`
		Period int    `json:"period"`
		Alg    string `json:"alg"`
		Code   string `json:"code"`
	}
	var cases []want
	for i := range 200 {
		// Secrets of many lengths, including ones that do not divide by five
		// and so exercise base32 padding on the way through.
		n := totp.MinSecret + i%23
		raw := make([]byte, n)
		if _, err := rand.Read(raw); err != nil {
			t.Fatal(err)
		}
		alg := []string{"SHA1", "SHA256", "SHA512"}[i%3]
		cases = append(cases, want{
			Secret: totp.FormatSecret(raw),
			Unix:   int64(1000000000 + i*97531),
			Digits: 6 + i%5,
			Period: []int{30, 60, 15, 45}[i%4],
			Alg:    alg,
		})
	}
	in, err := json.Marshal(cases)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(python, "-c", pythonTOTP)
	cmd.Stdin = strings.NewReader(string(in))
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("pyotp: %v", err)
	}
	if err := json.Unmarshal(out, &cases); err != nil {
		t.Fatalf("reading pyotp's answers: %v\n%s", err, out)
	}

	algs := map[string]totp.Algorithm{"SHA1": totp.SHA1, "SHA256": totp.SHA256, "SHA512": totp.SHA512}
	for _, c := range cases {
		secret, err := totp.ParseSecret(c.Secret)
		if err != nil {
			t.Fatal(err)
		}
		o := totp.Options{
			Digits:    c.Digits,
			Period:    time.Duration(c.Period) * time.Second,
			Algorithm: algs[c.Alg],
		}
		got, err := totp.At(secret, time.Unix(c.Unix, 0), o)
		if err != nil {
			t.Fatalf("%+v: %v", c, err)
		}
		if got != c.Code {
			t.Errorf("%s, %d digits, %ds, T=%d: this package says %s and pyotp says %s",
				c.Alg, c.Digits, c.Period, c.Unix, got, c.Code)
		}
	}
}

// pythonTOTP reads the cases on stdin and writes them back with the codes.
const pythonTOTP = `
import sys, json, hashlib, pyotp
cases = json.load(sys.stdin)
digests = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}
for c in cases:
    t = pyotp.TOTP(c["secret"], digits=c["digits"], interval=c["period"], digest=digests[c["alg"]])
    c["code"] = t.at(c["unix"])
json.dump(cases, sys.stdout)
`

// needPyOTP finds a python that has pyotp, or skips -- unless the environment
// says the judge must be there.
//
// ⛔ A skip in the lane that INSTALLS the judge is a lane that passes for the
// wrong reason, and it looks exactly like a lane that passed for the right
// one. The first run of this test in CI took 0.082s, which is not long enough
// to have started a Python: it had skipped, and nothing said so. So the lane
// sets TOTP_REQUIRE_JUDGE=1 and a missing pyotp fails there.
func needPyOTP(t *testing.T) string {
	t.Helper()
	for _, python := range []string{"python3", "python"} {
		p, err := exec.LookPath(python)
		if err != nil {
			continue
		}
		if err := exec.Command(p, "-c", "import pyotp").Run(); err == nil {
			return p
		}
	}
	if os.Getenv("TOTP_REQUIRE_JUDGE") != "" {
		t.Fatal("TOTP_REQUIRE_JUDGE is set and there is no python with pyotp: the independent implementation is the judge, and this lane exists to run it")
	}
	t.Skip("no python with pyotp here: the independent implementation is the judge, and the CI lane installs it")
	return ""
}
