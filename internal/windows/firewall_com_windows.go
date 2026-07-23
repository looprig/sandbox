//go:build windows

package windows

import (
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	coinitApartmentThreaded = 0x2
	clsctxInprocServer      = 0x1

	dispatchMethod      = 0x1
	dispatchPropertyGet = 0x2
	dispatchPropertyPut = 0x4
	dispidPropertyPut   = -3

	vtEmpty    = 0
	vtI4       = 3
	vtBSTR     = 8
	vtDispatch = 9
	vtBool     = 11
)

var (
	clsidNetFwPolicy2 = windows.GUID{Data1: 0xe2b3c97f, Data2: 0x6ae1, Data3: 0x41ac, Data4: [8]byte{0x81, 0x7a, 0xf6, 0xf9, 0x21, 0x66, 0xd7, 0xdd}}
	clsidNetFwRule    = windows.GUID{Data1: 0x2c5bc43e, Data2: 0x3369, Data3: 0x4c33, Data4: [8]byte{0xab, 0x0c, 0xbe, 0x94, 0x69, 0x67, 0x7a, 0xf4}}
	iidIDispatch      = windows.GUID{Data1: 0x00020400, Data4: [8]byte{0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}}
	iidNull           windows.GUID

	ole32                 = windows.NewLazySystemDLL("ole32.dll")
	oleaut32              = windows.NewLazySystemDLL("oleaut32.dll")
	procCoInitializeEx    = ole32.NewProc("CoInitializeEx")
	procCoUninitialize    = ole32.NewProc("CoUninitialize")
	procCoCreateInstance  = ole32.NewProc("CoCreateInstance")
	procSysAllocStringLen = oleaut32.NewProc("SysAllocStringLen")
	procSysFreeString     = oleaut32.NewProc("SysFreeString")
	procSysStringLen      = oleaut32.NewProc("SysStringLen")
	procVariantClear      = oleaut32.NewProc("VariantClear")
)

type oleVariant struct {
	Type     uint16
	reserved [3]uint16
	// The VARIANT union is eight bytes on both 32-bit and 64-bit Windows.
	Value uint64
}

type oleDispatchParams struct {
	Args            *oleVariant
	NamedArgIDs     *int32
	ArgCount        uint32
	NamedArgIDCount uint32
}

type oleExceptionInfo struct {
	Code, Reserved                uint16
	Source, Description, HelpFile uintptr
	HelpContext                   uint32
	ReservedPointer, DeferredFill uintptr
	ResultCode                    int32
}

type dispatchInvoker func(uintptr, ...uintptr) uintptr

type oleDispatch struct {
	object   unsafe.Pointer
	invoke   dispatchInvoker
	freeBSTR func(uintptr)
}

func syscallN(address uintptr, args ...uintptr) uintptr {
	result, _, _ := syscall.SyscallN(address, args...)
	return result
}

func (d *oleDispatch) release() {
	if d == nil || d.object == nil {
		return
	}
	vtable := *(*unsafe.Pointer)(d.object)
	d.invoke(*(*uintptr)(unsafe.Add(vtable, 2*unsafe.Sizeof(uintptr(0)))), uintptr(d.object))
	d.object = nil
}

func (d *oleDispatch) memberID(name string) (int32, error) {
	wide, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, fmt.Errorf("Windows Firewall COM member %q: %w", name, err)
	}
	names := [1]*uint16{wide}
	var id int32
	vtable := *(*unsafe.Pointer)(d.object)
	address := *(*uintptr)(unsafe.Add(vtable, 5*unsafe.Sizeof(uintptr(0))))
	hr := d.invoke(address, uintptr(d.object), uintptr(unsafe.Pointer(&iidNull)), uintptr(unsafe.Pointer(&names[0])), 1, 0x0409, uintptr(unsafe.Pointer(&id)))
	runtime.KeepAlive(names)
	if err := hresultError(hr); err != nil {
		return 0, fmt.Errorf("resolve Windows Firewall COM member %q: %w", name, err)
	}
	return id, nil
}

func (d *oleDispatch) invokeMember(name string, flags uint16, args []oleVariant) (oleVariant, error) {
	id, err := d.memberID(name)
	if err != nil {
		return oleVariant{}, err
	}
	// Automation arguments are right-to-left in DISPPARAMS. Copying preserves
	// caller ownership of BSTR and interface values.
	abiArgs := reverseVariants(args)
	params := oleDispatchParams{ArgCount: uint32(len(abiArgs))}
	if len(abiArgs) != 0 {
		params.Args = &abiArgs[0]
	}
	var propertyPutID int32
	if flags == dispatchPropertyPut {
		propertyPutID = dispidPropertyPut
		params.NamedArgIDs = &propertyPutID
		params.NamedArgIDCount = 1
	}
	var result oleVariant
	var exception oleExceptionInfo
	var argumentError uint32
	vtable := *(*unsafe.Pointer)(d.object)
	address := *(*uintptr)(unsafe.Add(vtable, 6*unsafe.Sizeof(uintptr(0))))
	hr := d.invoke(address, uintptr(d.object), uintptr(uint32(id)), uintptr(unsafe.Pointer(&iidNull)), 0x0409, uintptr(flags),
		uintptr(unsafe.Pointer(&params)), uintptr(unsafe.Pointer(&result)), uintptr(unsafe.Pointer(&exception)), uintptr(unsafe.Pointer(&argumentError)))
	runtime.KeepAlive(abiArgs)
	clearExceptionInfo(&exception, d.invoke, d.freeBSTR)
	if err := hresultError(hr); err != nil {
		clearVariant(&result)
		return oleVariant{}, fmt.Errorf("invoke Windows Firewall COM member %q: %w", name, err)
	}
	return result, nil
}

func reverseVariants(values []oleVariant) []oleVariant {
	if len(values) == 0 {
		return nil
	}
	reversed := make([]oleVariant, len(values))
	for index := range values {
		reversed[len(values)-1-index] = values[index]
	}
	return reversed
}

func clearExceptionInfo(info *oleExceptionInfo, invoker dispatchInvoker, freeBSTR func(uintptr)) {
	if info == nil {
		return
	}
	if info.DeferredFill != 0 {
		// COM specifies HRESULT (*)(EXCEPINFO*); it fills the BSTR fields.
		invoker(info.DeferredFill, uintptr(unsafe.Pointer(info)))
		info.DeferredFill = 0
	}
	if freeBSTR == nil {
		freeBSTR = func(value uintptr) { procSysFreeString.Call(value) }
	}
	for _, value := range []uintptr{info.Source, info.Description, info.HelpFile} {
		if value != 0 {
			freeBSTR(value)
		}
	}
	info.Source, info.Description, info.HelpFile = 0, 0, 0
}

func hresultError(result uintptr) error {
	hr := uint32(result)
	if int32(hr) >= 0 {
		return nil
	}
	return hresultCode(hr)
}

type hresultCode uint32

func (h hresultCode) Error() string { return fmt.Sprintf("HRESULT 0x%08x", uint32(h)) }

func clearVariant(value *oleVariant) {
	if value == nil || value.Type == vtEmpty {
		return
	}
	procVariantClear.Call(uintptr(unsafe.Pointer(value)))
}

func bstrVariant(value string) (oleVariant, error) {
	wide, err := windows.UTF16FromString(value)
	if err != nil {
		return oleVariant{}, err
	}
	ptr, _, _ := procSysAllocStringLen.Call(uintptr(unsafe.Pointer(&wide[0])), uintptr(len(wide)-1))
	runtime.KeepAlive(wide)
	if ptr == 0 {
		return oleVariant{}, errors.New("SysAllocStringLen failed")
	}
	return oleVariant{Type: vtBSTR, Value: uint64(ptr)}, nil
}

func (v oleVariant) stringValue(member string) (string, error) {
	if v.Type != vtBSTR {
		return "", fmt.Errorf("Windows Firewall COM member %q returned VARIANT type %d, want BSTR", member, v.Type)
	}
	// A null BSTR is Automation's valid representation of an empty string.
	if v.Value == 0 {
		return "", nil
	}
	length, _, _ := procSysStringLen.Call(uintptr(v.Value))
	pointer := *(*unsafe.Pointer)(unsafe.Pointer(&v.Value))
	return windows.UTF16ToString(unsafe.Slice((*uint16)(pointer), int(length))), nil
}

func (v oleVariant) int32Value(member string) (int32, error) {
	if v.Type != vtI4 {
		return 0, fmt.Errorf("Windows Firewall COM member %q returned VARIANT type %d, want I4", member, v.Type)
	}
	return int32(v.Value), nil
}

func (v oleVariant) boolValue(member string) (bool, error) {
	if v.Type != vtBool {
		return false, fmt.Errorf("Windows Firewall COM member %q returned VARIANT type %d, want BOOL", member, v.Type)
	}
	return int16(v.Value) != 0, nil
}

func (v oleVariant) dispatchValue(member string, invoker dispatchInvoker) (*oleDispatch, error) {
	if v.Type != vtDispatch || v.Value == 0 {
		return nil, fmt.Errorf("Windows Firewall COM member %q returned VARIANT type %d, want IDispatch", member, v.Type)
	}
	return &oleDispatch{object: *(*unsafe.Pointer)(unsafe.Pointer(&v.Value)), invoke: invoker}, nil
}

type rawNetFwAutomation struct {
	invoker dispatchInvoker
}

func newNetFwAutomation() netFwAutomation {
	return &rawNetFwAutomation{invoker: syscallN}
}

func (a *rawNetFwAutomation) withApartment(operation func() error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	hr, _, _ := procCoInitializeEx.Call(0, coinitApartmentThreaded)
	if err := hresultError(hr); err != nil {
		return fmt.Errorf("initialize Windows Firewall COM apartment: %w", err)
	}
	defer procCoUninitialize.Call()
	return operation()
}

func (a *rawNetFwAutomation) create(classID *windows.GUID) (*oleDispatch, error) {
	var object uintptr
	hr, _, _ := procCoCreateInstance.Call(uintptr(unsafe.Pointer(classID)), 0, clsctxInprocServer,
		uintptr(unsafe.Pointer(&iidIDispatch)), uintptr(unsafe.Pointer(&object)))
	if err := hresultError(hr); err != nil {
		return nil, fmt.Errorf("create Windows Firewall COM object: %w", err)
	}
	if object == 0 {
		return nil, errors.New("create Windows Firewall COM object returned nil IDispatch")
	}
	return &oleDispatch{object: *(*unsafe.Pointer)(unsafe.Pointer(&object)), invoke: a.invoker}, nil
}

func (a *rawNetFwAutomation) policyAndRules() (*oleDispatch, *oleDispatch, error) {
	policy, err := a.create(&clsidNetFwPolicy2)
	if err != nil {
		return nil, nil, err
	}
	value, err := policy.invokeMember("Rules", dispatchPropertyGet, nil)
	if err != nil {
		policy.release()
		return nil, nil, err
	}
	rules, err := value.dispatchValue("Rules", a.invoker)
	if err != nil {
		clearVariant(&value)
		policy.release()
		return nil, nil, err
	}
	// Ownership of the IDispatch reference moves from the VARIANT to rules.
	value.Type = vtEmpty
	return policy, rules, nil
}

func (a *rawNetFwAutomation) LocalPolicyModifyState() (state int32, err error) {
	err = a.withApartment(func() error {
		policy, createErr := a.create(&clsidNetFwPolicy2)
		if createErr != nil {
			return createErr
		}
		defer policy.release()
		value, invokeErr := policy.invokeMember("LocalPolicyModifyState", dispatchPropertyGet, nil)
		defer clearVariant(&value)
		if invokeErr != nil {
			return invokeErr
		}
		state, invokeErr = value.int32Value("LocalPolicyModifyState")
		return invokeErr
	})
	return state, err
}

func (a *rawNetFwAutomation) ReadRule(name string) (record netFwRuleRecord, found bool, err error) {
	err = a.withApartment(func() error {
		policy, rules, createErr := a.policyAndRules()
		if createErr != nil {
			return createErr
		}
		defer policy.release()
		defer rules.release()
		nameValue, valueErr := bstrVariant(name)
		if valueErr != nil {
			return valueErr
		}
		defer clearVariant(&nameValue)
		value, invokeErr := rules.invokeMember("Item", dispatchPropertyGet, []oleVariant{nameValue})
		if invokeErr != nil {
			// INetFwRules::Item reports ERROR_FILE_NOT_FOUND for an absent name.
			if errors.Is(invokeErr, errFirewallRuleNotFound) {
				return nil
			}
			return invokeErr
		}
		rule, valueErr := value.dispatchValue("Item", a.invoker)
		if valueErr != nil {
			clearVariant(&value)
			return valueErr
		}
		value.Type = vtEmpty
		defer rule.release()
		record, valueErr = readNetFwRule(rule)
		found = valueErr == nil
		return valueErr
	})
	return record, found, err
}

var errFirewallRuleNotFound error = hresultCode(0x80070002)

func (a *rawNetFwAutomation) WriteRule(record netFwRuleRecord) error {
	return a.withApartment(func() error {
		policy, rules, err := a.policyAndRules()
		if err != nil {
			return err
		}
		defer policy.release()
		defer rules.release()
		rule, err := a.create(&clsidNetFwRule)
		if err != nil {
			return err
		}
		defer rule.release()
		if err := writeNetFwRule(rule, record); err != nil {
			return err
		}
		argument := oleVariant{Type: vtDispatch, Value: uint64(uintptr(rule.object))}
		result, err := rules.invokeMember("Add", dispatchMethod, []oleVariant{argument})
		clearVariant(&result)
		return err
	})
}

func (a *rawNetFwAutomation) DeleteRule(name string) error {
	return a.withApartment(func() error {
		policy, rules, err := a.policyAndRules()
		if err != nil {
			return err
		}
		defer policy.release()
		defer rules.release()
		argument, err := bstrVariant(name)
		if err != nil {
			return err
		}
		defer clearVariant(&argument)
		result, err := rules.invokeMember("Remove", dispatchMethod, []oleVariant{argument})
		clearVariant(&result)
		return err
	})
}

func readNetFwRule(rule *oleDispatch) (netFwRuleRecord, error) {
	var record netFwRuleRecord
	stringFields := []struct {
		name string
		dst  *string
	}{{"Name", &record.Name}, {"Grouping", &record.Grouping}, {"LocalAddresses", &record.LocalAddresses},
		{"RemoteAddresses", &record.RemoteAddresses}, {"LocalPorts", &record.LocalPorts},
		{"RemotePorts", &record.RemotePorts}, {"LocalUserAuthorizedList", &record.LocalUserAuthorizedList}}
	for _, field := range stringFields {
		value, err := rule.invokeMember(field.name, dispatchPropertyGet, nil)
		if err != nil {
			return netFwRuleRecord{}, err
		}
		*field.dst, err = value.stringValue(field.name)
		clearVariant(&value)
		if err != nil {
			return netFwRuleRecord{}, err
		}
	}
	intFields := []struct {
		name string
		dst  *int32
	}{{"Profiles", &record.Profiles}, {"Direction", &record.Direction}, {"Action", &record.Action}, {"Protocol", &record.Protocol}}
	for _, field := range intFields {
		value, err := rule.invokeMember(field.name, dispatchPropertyGet, nil)
		if err != nil {
			return netFwRuleRecord{}, err
		}
		*field.dst, err = value.int32Value(field.name)
		clearVariant(&value)
		if err != nil {
			return netFwRuleRecord{}, err
		}
	}
	value, err := rule.invokeMember("Enabled", dispatchPropertyGet, nil)
	if err != nil {
		return netFwRuleRecord{}, err
	}
	record.Enabled, err = value.boolValue("Enabled")
	clearVariant(&value)
	return record, err
}

func writeNetFwRule(rule *oleDispatch, record netFwRuleRecord) error {
	intFields := []struct {
		name  string
		value int32
	}{{"Profiles", record.Profiles}, {"Direction", record.Direction}, {"Action", record.Action}, {"Protocol", record.Protocol}}
	for _, field := range intFields {
		result, err := rule.invokeMember(field.name, dispatchPropertyPut, []oleVariant{{Type: vtI4, Value: uint64(uint32(field.value))}})
		clearVariant(&result)
		if err != nil {
			return err
		}
	}
	stringFields := []struct{ name, value string }{
		{"Name", record.Name}, {"Grouping", record.Grouping}, {"LocalAddresses", record.LocalAddresses},
		{"RemoteAddresses", record.RemoteAddresses}, {"LocalPorts", record.LocalPorts},
		{"RemotePorts", record.RemotePorts}, {"LocalUserAuthorizedList", record.LocalUserAuthorizedList},
	}
	for _, field := range stringFields {
		value, err := bstrVariant(field.value)
		if err != nil {
			return err
		}
		result, invokeErr := rule.invokeMember(field.name, dispatchPropertyPut, []oleVariant{value})
		clearVariant(&result)
		clearVariant(&value)
		if invokeErr != nil {
			return invokeErr
		}
	}
	var boolValue uint64
	if record.Enabled {
		boolValue = uint64(^uint16(0))
	}
	result, err := rule.invokeMember("Enabled", dispatchPropertyPut, []oleVariant{{Type: vtBool, Value: boolValue}})
	clearVariant(&result)
	return err
}
