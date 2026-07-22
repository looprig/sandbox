//go:build windows

package windows

import (
	"errors"
	"fmt"

	xwindows "golang.org/x/sys/windows"
)

const tokenElevationTypeLimited = 3

var errDisposableSourceTokenIneligible = errors.New("windows sandbox: disposable worker requires a genuine non-administrator standard-user source token")

type sourceTokenShape struct {
	restricted         bool
	elevated           bool
	administrator      bool
	splitAdministrator bool
}

// ValidateDisposableStandardUserToken verifies the source-token prerequisite
// shared by destructive live Windows acceptance suites. A UAC-filtered
// administrator is deliberately not a standard user: its disabled
// Administrators SID and limited elevation type still identify an account that
// can cross the administrative boundary outside the sandbox under test.
func ValidateDisposableStandardUserToken(token xwindows.Token) error {
	restricted, err := token.IsRestricted()
	if err != nil {
		return fmt.Errorf("inspect restricted-token state: %w", err)
	}
	elevationType, err := tokenUint32Information(token, xwindows.TokenElevationType)
	if err != nil {
		return fmt.Errorf("inspect token elevation type: %w", err)
	}
	groups, err := token.GetTokenGroups()
	if err != nil {
		return fmt.Errorf("inspect token groups: %w", err)
	}
	administrators, err := xwindows.StringToSid("S-1-5-32-544")
	if err != nil {
		return fmt.Errorf("construct Administrators SID: %w", err)
	}
	shape := sourceTokenShape{
		restricted:         restricted,
		elevated:           token.IsElevated(),
		administrator:      sidInGroups(groups.AllGroups(), administrators),
		splitAdministrator: elevationType == tokenElevationTypeLimited,
	}
	return validateDisposableSourceTokenShape(shape)
}

func validateDisposableSourceTokenShape(shape sourceTokenShape) error {
	if shape.restricted {
		return fmt.Errorf("%w: source token is restricted", errDisposableSourceTokenIneligible)
	}
	if shape.elevated {
		return fmt.Errorf("%w: source token is elevated", errDisposableSourceTokenIneligible)
	}
	if shape.administrator || shape.splitAdministrator {
		return fmt.Errorf("%w: source account belongs to Administrators or has a UAC split token", errDisposableSourceTokenIneligible)
	}
	return nil
}
