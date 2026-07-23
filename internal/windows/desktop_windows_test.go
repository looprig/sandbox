//go:build windows

package windows

import (
	"errors"
	"reflect"
	"testing"

	win "golang.org/x/sys/windows"
)

type fakePrivateDesktopAPI struct {
	calls  []string
	failAt string
}

func (api *fakePrivateDesktopAPI) call(name string) error {
	api.calls = append(api.calls, name)
	if api.failAt == name {
		return errors.New("injected")
	}
	return nil
}
func (api *fakePrivateDesktopAPI) CreateWindowStation(string, *win.SECURITY_DESCRIPTOR) (desktopHandle, error) {
	return 1, api.call("create-station")
}
func (api *fakePrivateDesktopAPI) CreateDesktop(string, desktopHandle, *win.SECURITY_DESCRIPTOR) (desktopHandle, error) {
	return 2, api.call("create-desktop")
}
func (api *fakePrivateDesktopAPI) VerifyProtectedACL(handle desktopHandle, _ *win.SECURITY_DESCRIPTOR) error {
	if handle == 1 {
		return api.call("verify-station")
	}
	return api.call("verify-desktop")
}
func (api *fakePrivateDesktopAPI) CloseWindowStation(desktopHandle) error {
	return api.call("close-station")
}
func (api *fakePrivateDesktopAPI) CloseDesktop(desktopHandle) error {
	return api.call("close-desktop")
}

func TestPrivateDesktopIsProtectedBeforeItIsReturned(t *testing.T) {
	api := &fakePrivateDesktopAPI{}
	factory, err := newPrivateDesktopFactory(api)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := protectedDesktopDescriptorForTest(t)
	desktop, err := factory.Create(privateDesktopSpec{
		WindowStation:      "sandbox-nonce",
		Desktop:            "default",
		SecurityDescriptor: descriptor,
	})
	if err != nil {
		t.Fatal(err)
	}
	if desktop.Name != `sandbox-nonce\default` {
		t.Fatalf("desktop name = %q", desktop.Name)
	}
	want := []string{"create-station", "verify-station", "create-desktop", "verify-desktop"}
	if !reflect.DeepEqual(api.calls, want) {
		t.Fatalf("calls = %v, want %v", api.calls, want)
	}
	if err := desktop.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestPrivateDesktopFailsClosedAtEveryBoundary(t *testing.T) {
	for _, failAt := range []string{"create-station", "verify-station", "create-desktop", "verify-desktop"} {
		t.Run(failAt, func(t *testing.T) {
			api := &fakePrivateDesktopAPI{failAt: failAt}
			factory, _ := newPrivateDesktopFactory(api)
			if _, err := factory.Create(privateDesktopSpec{
				WindowStation: "sandbox", Desktop: "default",
				SecurityDescriptor: protectedDesktopDescriptorForTest(t),
			}); err == nil {
				t.Fatal("Create succeeded despite injected failure")
			}
			if failAt != "create-station" && api.calls[len(api.calls)-1] != "close-station" {
				t.Fatalf("station not closed after %s: %v", failAt, api.calls)
			}
			if failAt == "verify-desktop" {
				if api.calls[len(api.calls)-2] != "close-desktop" {
					t.Fatalf("desktop not closed after %s: %v", failAt, api.calls)
				}
			}
		})
	}
}

func TestPrivateDesktopRejectsInteractiveAndMalformedNames(t *testing.T) {
	factory, _ := newPrivateDesktopFactory(&fakePrivateDesktopAPI{})
	for _, spec := range []privateDesktopSpec{
		{WindowStation: "WinSta0", Desktop: "Default", SecurityDescriptor: protectedDesktopDescriptorForTest(t)},
		{WindowStation: `WinSta0\Default`, Desktop: "x", SecurityDescriptor: protectedDesktopDescriptorForTest(t)},
		{WindowStation: "x", Desktop: `WinSta0\Default`, SecurityDescriptor: protectedDesktopDescriptorForTest(t)},
	} {
		if _, err := factory.Create(spec); err == nil {
			t.Fatalf("accepted invalid desktop spec: %+v", spec)
		}
	}
}

func TestPrivateDesktopRejectsUnprotectedDescriptorBeforeNativeCalls(t *testing.T) {
	api := &fakePrivateDesktopAPI{}
	factory, _ := newPrivateDesktopFactory(api)
	descriptor, err := win.SecurityDescriptorFromString("D:(A;;GA;;;SY)")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := factory.Create(privateDesktopSpec{
		WindowStation: "sandbox", Desktop: "default", SecurityDescriptor: descriptor,
	}); err == nil {
		t.Fatal("unprotected descriptor accepted")
	}
	if len(api.calls) != 0 {
		t.Fatalf("native calls made for unprotected descriptor: %v", api.calls)
	}
}

func TestExactDesktopSecurityRejectsBroaderDACLAndWrongOwner(t *testing.T) {
	expected, err := win.SecurityDescriptorFromString("O:SYD:P(A;;GA;;;SY)")
	if err != nil {
		t.Fatal(err)
	}
	for name, sddl := range map[string]string{
		"broader":     "O:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)",
		"wrong owner": "O:BAD:P(A;;GA;;;SY)",
	} {
		t.Run(name, func(t *testing.T) {
			actual, err := win.SecurityDescriptorFromString(sddl)
			if err != nil {
				t.Fatal(err)
			}
			if err := verifyExactDesktopSecurity(actual, expected); err == nil {
				t.Fatal("mismatched security descriptor accepted")
			}
		})
	}
	if err := verifyExactDesktopSecurity(expected, expected); err != nil {
		t.Fatalf("exact security descriptor rejected: %v", err)
	}
}

func protectedDesktopDescriptorForTest(t *testing.T) *win.SECURITY_DESCRIPTOR {
	t.Helper()
	descriptor, err := win.SecurityDescriptorFromString("O:SYD:P(A;;GA;;;SY)")
	if err != nil {
		t.Fatal(err)
	}
	return descriptor
}
