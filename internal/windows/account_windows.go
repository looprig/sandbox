//go:build windows

package windows

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"slices"
	"strings"
)

const accountPasswordAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*-_=+"

const (
	windowsLocalAccountNameLimit = 20
	windowsUsersGroup            = `BUILTIN\Users`
	serviceLogonRight            = "SeServiceLogonRight"
	interactiveLogonRight        = "SeDenyInteractiveLogonRight"
	remoteInteractiveLogonRight  = "SeDenyRemoteInteractiveLogonRight"
	networkLogonRight            = "SeDenyNetworkLogonRight"
)

var (
	errAccountNotFound          = errors.New("sandbox: Windows account not found")
	errAccountOwnershipMismatch = errors.New("sandbox: Windows account ownership mismatch")
)

type installationPrincipalNames struct {
	Offline string
	Online  string
	Service string
}

func deriveInstallationPrincipalNames(installationID string) (installationPrincipalNames, error) {
	if strings.TrimSpace(installationID) == "" {
		return installationPrincipalNames{}, errors.New("sandbox: Windows installation identity is required")
	}
	digest := sha256.Sum256([]byte(installationID))
	suffix := hex.EncodeToString(digest[:])[:12]
	return installationPrincipalNames{
		Offline: "lsb-o-" + suffix,
		Online:  "lsb-n-" + suffix,
		Service: "lsb-svc-" + suffix,
	}, nil
}

type sandboxAccountPolicy struct {
	PasswordNeverExpires bool
	HiddenFromUI         bool
	Groups               []string
	Rights               []string
	DenyRights           []string
}

func requiredSandboxAccountPolicy() sandboxAccountPolicy {
	return sandboxAccountPolicy{
		PasswordNeverExpires: true,
		HiddenFromUI:         true,
		Groups:               []string{windowsUsersGroup},
		Rights:               []string{serviceLogonRight},
		DenyRights:           []string{interactiveLogonRight, remoteInteractiveLogonRight, networkLogonRight},
	}
}

func (policy sandboxAccountPolicy) equal(other sandboxAccountPolicy) bool {
	return policy.PasswordNeverExpires == other.PasswordNeverExpires &&
		policy.HiddenFromUI == other.HiddenFromUI &&
		equalStringSets(policy.Groups, other.Groups) &&
		equalStringSets(policy.Rights, other.Rights) &&
		equalStringSets(policy.DenyRights, other.DenyRights)
}

func equalStringSets(left, right []string) bool {
	left, right = append([]string(nil), left...), append([]string(nil), right...)
	slices.Sort(left)
	slices.Sort(right)
	return slices.Equal(left, right)
}

type sandboxAccountRecord struct {
	Name   string
	SID    string
	Owned  bool
	Policy sandboxAccountPolicy
}

// accountAPI is deliberately transactional at the policy boundary. The real
// NetAPI/LSA adapter must either apply the complete record or return an error;
// callers never infer ownership merely from a matching account name.
type accountAPI interface {
	Lookup(name string) (sandboxAccountRecord, error)
	Create(record sandboxAccountRecord, password []byte) (sandboxAccountRecord, error)
	ApplyPolicy(record sandboxAccountRecord) error
	SetPassword(name string, password []byte) error
	Delete(name string) error
}

func reconcileSandboxAccount(api accountAPI, name string, password []byte, rotate bool) (sandboxAccountRecord, error) {
	defer zeroBytes(password)
	policy := requiredSandboxAccountPolicy()
	record, err := api.Lookup(name)
	if errors.Is(err, errAccountNotFound) {
		if len(password) == 0 {
			return sandboxAccountRecord{}, errors.New("sandbox: empty Windows account credential")
		}
		return api.Create(sandboxAccountRecord{Name: name, Owned: true, Policy: policy}, password)
	}
	if err != nil {
		return sandboxAccountRecord{}, err
	}
	if !record.Owned || record.Name != name || record.SID == "" {
		return sandboxAccountRecord{}, errAccountOwnershipMismatch
	}
	if !record.Policy.equal(policy) {
		record.Policy = policy
		if err := api.ApplyPolicy(record); err != nil {
			return sandboxAccountRecord{}, err
		}
	}
	if rotate {
		if len(password) == 0 {
			return sandboxAccountRecord{}, errors.New("sandbox: empty Windows account credential")
		}
		if err := api.SetPassword(name, password); err != nil {
			return sandboxAccountRecord{}, err
		}
	}
	return record, nil
}

func removeSandboxAccount(api accountAPI, name, manifestSID string) error {
	if name == "" || manifestSID == "" {
		return errAccountOwnershipMismatch
	}
	record, err := api.Lookup(name)
	if errors.Is(err, errAccountNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if !record.Owned || record.Name != name || record.SID != manifestSID {
		return errAccountOwnershipMismatch
	}
	return api.Delete(name)
}

func zeroBytes(data []byte) {
	for index := range data {
		data[index] = 0
	}
}

func newAccountPassword(random io.Reader, length int) ([]byte, error) {
	if random == nil || length < 32 {
		return nil, errors.New("sandbox: Windows account password length is too small")
	}
	password := make([]byte, length)
	randomByte := []byte{0}
	// Rejection sampling avoids modulo bias while keeping the result directly
	// consumable as a mutable buffer that can be wiped after NetUserSetInfo.
	limit := byte(256 - (256 % len(accountPasswordAlphabet)))
	for index := range password {
		for {
			if _, err := io.ReadFull(random, randomByte); err != nil {
				zeroBytes(password)
				return nil, err
			}
			if randomByte[0] < limit {
				password[index] = accountPasswordAlphabet[int(randomByte[0])%len(accountPasswordAlphabet)]
				break
			}
		}
	}
	return password, nil
}
