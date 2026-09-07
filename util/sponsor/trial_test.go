package sponsor

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func signToken(t *testing.T, subject string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:  "evcc.io",
		Subject: subject,
	})
	s, err := tok.SignedString([]byte("secret"))
	require.NoError(t, err)
	return s
}

func TestParseTrialToken(t *testing.T) {
	trial := signToken(t, "trial")
	other := signToken(t, "someone@example.com")

	// page embeds an unrelated token first, then the trial token inside markup
	body := []byte("<p>example: <code>" + other + "</code></p>\n<pre><code>" + trial + "</code></pre>")

	got, err := parseTrialToken(body)
	require.NoError(t, err)
	assert.Equal(t, trial, got)
}

func TestParseTrialTokenMissing(t *testing.T) {
	body := []byte("<p>no token here</p><code>" + signToken(t, "paid") + "</code>")

	_, err := parseTrialToken(body)
	assert.Error(t, err)
}
