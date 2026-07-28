//go:build windows

package policy

import (
	"encoding/hex"
	"fmt"

	"github.com/looprig/sandbox/internal/winpath"
)

func FileIdentity(path string) (string, error) {
	object, err := winpath.Open(path)
	if err != nil {
		return "", err
	}
	defer object.Close()
	return windowsObjectIdentity(object), nil
}

func windowsObjectIdentity(object *winpath.Object) string {
	return fmt.Sprintf("%016x:%s:%d:%08x:%d:%s", object.VolumeSerial,
		hex.EncodeToString(object.FileID[:]), object.Kind, object.ReparseTag,
		object.LinkCount, object.PathKey)
}
