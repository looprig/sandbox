//go:build windows

package windows

import (
	"errors"
	"strings"
	"testing"
	"unsafe"
)

func TestOleVariantHasWindowsABISize(t *testing.T) {
	if got := unsafe.Sizeof(oleVariant{}); got != 16 {
		t.Fatalf("VARIANT size = %d, want 16", got)
	}
	wantExceptionSize := uintptr(32)
	if unsafe.Sizeof(uintptr(0)) == 8 {
		wantExceptionSize = 64
	}
	if got := unsafe.Sizeof(oleExceptionInfo{}); got != wantExceptionSize {
		t.Fatalf("EXCEPINFO size = %d, want %d", got, wantExceptionSize)
	}
}

func TestOleDispatchPropertyPutUsesDispatchABI(t *testing.T) {
	const (
		getIDsAddress = uintptr(0x1111)
		invokeAddress = uintptr(0x2222)
		memberID      = int32(73)
	)
	vtable := [7]uintptr{}
	vtable[5] = getIDsAddress
	vtable[6] = invokeAddress
	vtablePointer := uintptr(unsafe.Pointer(&vtable[0]))
	object := unsafe.Pointer(&vtablePointer)
	var gotInvoke bool
	caller := func(address uintptr, args ...uintptr) uintptr {
		switch address {
		case getIDsAddress:
			if len(args) != 6 || args[0] != uintptr(object) {
				t.Fatalf("GetIDsOfNames args = %#v", args)
			}
			*(*int32)(pointerBits(args[5])) = memberID
			return 0
		case invokeAddress:
			gotInvoke = true
			if len(args) != 9 || args[0] != uintptr(object) || int32(args[1]) != memberID {
				t.Fatalf("Invoke args = %#v", args)
			}
			if args[4] != dispatchPropertyPut {
				t.Fatalf("Invoke flags = %d", args[4])
			}
			params := (*oleDispatchParams)(pointerBits(args[5]))
			if params.ArgCount != 1 || params.NamedArgIDCount != 1 || params.NamedArgIDs == nil || *params.NamedArgIDs != dispidPropertyPut {
				t.Fatalf("DISPPARAMS = %#v", *params)
			}
			if params.Args.Type != vtI4 || params.Args.Value != 42 {
				t.Fatalf("argument = %#v", *params.Args)
			}
			*(*oleVariant)(pointerBits(args[6])) = oleVariant{Type: vtI4, Value: 9}
			return 0
		default:
			t.Fatalf("unexpected ABI address %#x", address)
			return 0
		}
	}
	dispatch := &oleDispatch{object: object, invoke: caller}
	result, err := dispatch.invokeMember("Profiles", dispatchPropertyPut, []oleVariant{{Type: vtI4, Value: 42}})
	if err != nil {
		t.Fatal(err)
	}
	if !gotInvoke || result.Type != vtI4 || result.Value != 9 {
		t.Fatalf("result = %#v, invoked = %v", result, gotInvoke)
	}
}

func TestOleDispatchRejectsFailedHRESULTAndWrongVariantType(t *testing.T) {
	vtable := [7]uintptr{}
	vtable[5] = 1
	vtable[6] = 2
	vtablePointer := uintptr(unsafe.Pointer(&vtable[0]))
	object := unsafe.Pointer(&vtablePointer)
	failInvoke := false
	dispatch := &oleDispatch{object: object, invoke: func(address uintptr, args ...uintptr) uintptr {
		if address == 1 {
			*(*int32)(pointerBits(args[5])) = 1
			return 0
		}
		if failInvoke {
			return uintptr(hresultCode(0x80070005))
		}
		*(*oleVariant)(pointerBits(args[6])) = oleVariant{Type: vtBSTR}
		return 0
	}}
	value, err := dispatch.invokeMember("Enabled", dispatchPropertyGet, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := value.boolValue("Enabled"); err == nil || !strings.Contains(err.Error(), "want BOOL") {
		t.Fatalf("type error = %v", err)
	}
	failInvoke = true
	if _, err := dispatch.invokeMember("Enabled", dispatchPropertyGet, nil); err == nil || !strings.Contains(err.Error(), "0x80070005") {
		t.Fatalf("HRESULT error = %v", err)
	}
}

func TestHRESULTFileNotFoundClassificationIsExact(t *testing.T) {
	if !errors.Is(hresultCode(0x80070002), errFirewallRuleNotFound) {
		t.Fatal("ERROR_FILE_NOT_FOUND did not classify as an absent firewall rule")
	}
	if errors.Is(hresultCode(0x80070005), errFirewallRuleNotFound) {
		t.Fatal("access denied classified as an absent firewall rule")
	}
}

func TestReverseVariantsUsesAutomationArgumentOrder(t *testing.T) {
	got := reverseVariants([]oleVariant{{Value: 1}, {Value: 2}, {Value: 3}})
	if len(got) != 3 || got[0].Value != 3 || got[1].Value != 2 || got[2].Value != 1 {
		t.Fatalf("ABI arguments = %#v", got)
	}
}

func TestClearExceptionInfoFillsThenFreesEveryBSTR(t *testing.T) {
	info := oleExceptionInfo{DeferredFill: 99}
	var filled bool
	var freed []uintptr
	clearExceptionInfo(&info, func(address uintptr, args ...uintptr) uintptr {
		if address != 99 || len(args) != 1 {
			t.Fatalf("deferred fill call = %#x, %#v", address, args)
		}
		filled = true
		target := (*oleExceptionInfo)(pointerBits(args[0]))
		target.Source, target.Description, target.HelpFile = 10, 20, 30
		return 0
	}, func(value uintptr) {
		freed = append(freed, value)
	})
	if !filled || len(freed) != 3 || freed[0] != 10 || freed[1] != 20 || freed[2] != 30 {
		t.Fatalf("filled = %v, freed = %#v", filled, freed)
	}
	if info.Source != 0 || info.Description != 0 || info.HelpFile != 0 || info.DeferredFill != 0 {
		t.Fatalf("EXCEPINFO was not zeroed: %#v", info)
	}
}

func pointerBits(value uintptr) unsafe.Pointer {
	return *(*unsafe.Pointer)(unsafe.Pointer(&value))
}
