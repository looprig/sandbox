//go:build windows

package windows

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"unsafe"

	win "golang.org/x/sys/windows"
)

const (
	desktopAllAccess       = 0x000F01FF
	windowStationAllAccess = 0x000F037F
)

var (
	user32                   = win.NewLazySystemDLL("user32.dll")
	createWindowStationW     = user32.NewProc("CreateWindowStationW")
	closeWindowStation       = user32.NewProc("CloseWindowStation")
	getProcessWindowStation  = user32.NewProc("GetProcessWindowStation")
	setProcessWindowStation  = user32.NewProc("SetProcessWindowStation")
	createDesktopW           = user32.NewProc("CreateDesktopW")
	closeDesktop             = user32.NewProc("CloseDesktop")
	errInvalidPrivateDesktop = errors.New("windows sandbox: invalid private desktop specification")
	errUnprotectedDesktopACL = errors.New("windows sandbox: private desktop DACL is not protected")
	nativeDesktopStationMu   sync.Mutex
)

type desktopHandle win.Handle

// privateDesktopSpec is deliberately descriptor-driven. The caller must supply
// the complete protected DACL selected by the broker; the desktop layer has no
// authority to invent or widen trustees.
type privateDesktopSpec struct {
	WindowStation      string
	Desktop            string
	SecurityDescriptor *win.SECURITY_DESCRIPTOR
}

type privateDesktopAPI interface {
	CreateWindowStation(string, *win.SECURITY_DESCRIPTOR) (desktopHandle, error)
	CreateDesktop(string, desktopHandle, *win.SECURITY_DESCRIPTOR) (desktopHandle, error)
	VerifyProtectedACL(desktopHandle, *win.SECURITY_DESCRIPTOR) error
	CloseWindowStation(desktopHandle) error
	CloseDesktop(desktopHandle) error
}

type privateDesktopFactory struct {
	api privateDesktopAPI
}

type privateDesktop struct {
	Name          string
	windowStation desktopHandle
	desktop       desktopHandle
	api           privateDesktopAPI
}

func newPrivateDesktopFactory(api privateDesktopAPI) (*privateDesktopFactory, error) {
	if api == nil {
		return nil, errors.New("windows sandbox: private desktop API is required")
	}
	return &privateDesktopFactory{api: api}, nil
}

func (factory *privateDesktopFactory) Create(spec privateDesktopSpec) (_ *privateDesktop, err error) {
	if factory == nil || factory.api == nil || !validDesktopComponent(spec.WindowStation) ||
		!validDesktopComponent(spec.Desktop) || strings.EqualFold(spec.WindowStation, "WinSta0") ||
		spec.SecurityDescriptor == nil {
		return nil, errInvalidPrivateDesktop
	}
	if err := validateProtectedDesktopDescriptor(spec.SecurityDescriptor); err != nil {
		return nil, err
	}
	station, err := factory.api.CreateWindowStation(spec.WindowStation, spec.SecurityDescriptor)
	if err != nil {
		return nil, fmt.Errorf("windows sandbox: create private window station: %w", err)
	}
	defer func() {
		if err != nil {
			_ = factory.api.CloseWindowStation(station)
		}
	}()
	if err = factory.api.VerifyProtectedACL(station, spec.SecurityDescriptor); err != nil {
		return nil, fmt.Errorf("windows sandbox: verify private window station: %w", err)
	}

	desktop, err := factory.api.CreateDesktop(spec.Desktop, station, spec.SecurityDescriptor)
	if err != nil {
		return nil, fmt.Errorf("windows sandbox: create private desktop: %w", err)
	}
	defer func() {
		if err != nil {
			_ = factory.api.CloseDesktop(desktop)
		}
	}()
	if err = factory.api.VerifyProtectedACL(desktop, spec.SecurityDescriptor); err != nil {
		return nil, fmt.Errorf("windows sandbox: verify private desktop: %w", err)
	}
	return &privateDesktop{
		Name:          spec.WindowStation + `\` + spec.Desktop,
		windowStation: station,
		desktop:       desktop,
		api:           factory.api,
	}, nil
}

func validateProtectedDesktopDescriptor(descriptor *win.SECURITY_DESCRIPTOR) error {
	if descriptor == nil {
		return errInvalidPrivateDesktop
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return errors.Join(errUnprotectedDesktopACL, err)
	}
	control, _, err := descriptor.Control()
	if err != nil {
		return err
	}
	if control&win.SE_DACL_PROTECTED == 0 {
		return errUnprotectedDesktopACL
	}
	return nil
}

func (desktop *privateDesktop) Close() error {
	if desktop == nil || desktop.api == nil {
		return nil
	}
	err := desktop.api.CloseDesktop(desktop.desktop)
	err = errors.Join(err, desktop.api.CloseWindowStation(desktop.windowStation))
	desktop.api = nil
	return err
}

func validDesktopComponent(value string) bool {
	return value != "" && len(value) <= 128 && !strings.ContainsAny(value, `\/`+"\x00") &&
		value != "." && value != ".."
}

type nativePrivateDesktopAPI struct {
}

func (api *nativePrivateDesktopAPI) CreateWindowStation(name string, descriptor *win.SECURITY_DESCRIPTOR) (desktopHandle, error) {
	name16, err := win.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	attributes := win.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(win.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}
	handle, _, callErr := createWindowStationW.Call(
		uintptr(unsafe.Pointer(name16)), 0, windowStationAllAccess, uintptr(unsafe.Pointer(&attributes)),
	)
	if handle == 0 {
		return 0, callErr
	}
	return desktopHandle(handle), nil
}

func (api *nativePrivateDesktopAPI) CreateDesktop(name string, station desktopHandle, descriptor *win.SECURITY_DESCRIPTOR) (desktopHandle, error) {
	if station == 0 {
		return 0, errors.New("windows sandbox: desktop window station is missing")
	}
	name16, err := win.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	nativeDesktopStationMu.Lock()
	defer nativeDesktopStationMu.Unlock()
	previous, _, previousErr := getProcessWindowStation.Call()
	if previous == 0 {
		return 0, previousErr
	}
	ok, _, setErr := setProcessWindowStation.Call(uintptr(station))
	if ok == 0 {
		return 0, setErr
	}
	// CreateDesktop creates on the process window station, so select the exact
	// retained station only for this call and restore the host's station before
	// returning.
	attributes := win.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(win.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}
	handle, _, callErr := createDesktopW.Call(
		uintptr(unsafe.Pointer(name16)), 0, 0, 0, desktopAllAccess, uintptr(unsafe.Pointer(&attributes)),
	)
	restored, _, restoreErr := setProcessWindowStation.Call(previous)
	if restored == 0 {
		if handle != 0 {
			_, _, _ = closeDesktop.Call(handle)
		}
		return 0, fmt.Errorf("windows sandbox: restore process window station: %w", restoreErr)
	}
	if handle == 0 {
		return 0, callErr
	}
	return desktopHandle(handle), nil
}

func (*nativePrivateDesktopAPI) VerifyProtectedACL(handle desktopHandle, expected *win.SECURITY_DESCRIPTOR) error {
	descriptor, err := win.GetSecurityInfo(
		win.Handle(handle), win.SE_WINDOW_OBJECT,
		win.OWNER_SECURITY_INFORMATION|win.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return err
	}
	return verifyExactDesktopSecurity(descriptor, expected)
}

func verifyExactDesktopSecurity(actual, expected *win.SECURITY_DESCRIPTOR) error {
	if actual == nil || expected == nil {
		return errUnprotectedDesktopACL
	}
	actualOwner, _, err := actual.Owner()
	if err != nil {
		return err
	}
	expectedOwner, _, err := expected.Owner()
	if err != nil || actualOwner == nil || expectedOwner == nil || !actualOwner.Equals(expectedOwner) {
		return errors.Join(errors.New("windows sandbox: private desktop owner mismatch"), err)
	}
	actualDACL, _, err := actual.DACL()
	if err != nil {
		return err
	}
	expectedDACL, _, err := expected.DACL()
	if err != nil || actualDACL == nil || expectedDACL == nil || !equalDesktopACL(actualDACL, expectedDACL) {
		return errors.Join(errors.New("windows sandbox: private desktop DACL mismatch"), err)
	}
	control, _, err := actual.Control()
	if err != nil {
		return err
	}
	if control&win.SE_DACL_PROTECTED == 0 {
		return errUnprotectedDesktopACL
	}
	return nil
}

func equalDesktopACL(left, right *win.ACL) bool {
	type aclHeader struct {
		Revision byte
		Sbz1     byte
		Size     uint16
		AceCount uint16
		Sbz2     uint16
	}
	leftHeader := (*aclHeader)(unsafe.Pointer(left))
	rightHeader := (*aclHeader)(unsafe.Pointer(right))
	if leftHeader.Size < uint16(unsafe.Sizeof(aclHeader{})) || rightHeader.Size < uint16(unsafe.Sizeof(aclHeader{})) ||
		leftHeader.Size != rightHeader.Size {
		return false
	}
	leftBytes := unsafe.Slice((*byte)(unsafe.Pointer(left)), int(leftHeader.Size))
	rightBytes := unsafe.Slice((*byte)(unsafe.Pointer(right)), int(rightHeader.Size))
	return string(leftBytes) == string(rightBytes)
}

func (*nativePrivateDesktopAPI) CloseWindowStation(handle desktopHandle) error {
	if handle == 0 {
		return nil
	}
	ok, _, err := closeWindowStation.Call(uintptr(handle))
	if ok == 0 {
		return err
	}
	return nil
}

func (*nativePrivateDesktopAPI) CloseDesktop(handle desktopHandle) error {
	if handle == 0 {
		return nil
	}
	ok, _, err := closeDesktop.Call(uintptr(handle))
	if ok == 0 {
		return err
	}
	return nil
}
