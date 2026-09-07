package sponsor

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/evcc-io/evcc/util"
	"github.com/evcc-io/evcc/util/request"
	"github.com/golang-jwt/jwt/v5"
)

// TrialTokenURL is the documentation page that publishes the current trial sponsor token.
const TrialTokenURL = "https://docs.evcc.io/en/sponsorship/"

// trialSubject identifies the trial token amongst any other JWTs on the page.
const trialSubject = "trial"

// jwtRE matches a JWT (three base64url-encoded segments separated by dots).
var jwtRE = regexp.MustCompile(`eyJ[\w-]+\.eyJ[\w-]+\.[\w-]+`)

// TrialToken fetches the current trial sponsor token published on the evcc
// documentation page. It returns the JWT whose subject is "trial".
func TrialToken() (string, error) {
	body, err := request.NewHelper(util.NewLogger("sponsor")).GetBody(TrialTokenURL)
	if err != nil {
		return "", fmt.Errorf("fetching trial token: %w", err)
	}

	return parseTrialToken(body)
}

// parseTrialToken extracts the JWT with subject "trial" from the given page body.
func parseTrialToken(body []byte) (string, error) {
	parser := jwt.NewParser()
	for _, match := range jwtRE.FindAllString(string(body), -1) {
		var claims jwt.RegisteredClaims
		if _, _, err := parser.ParseUnverified(match, &claims); err != nil {
			continue
		}
		if claims.Subject == trialSubject {
			return match, nil
		}
	}

	return "", errors.New("no trial token found on " + TrialTokenURL)
}
