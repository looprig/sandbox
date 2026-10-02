package exec

import (
	"testing"

	"github.com/looprig/sandbox/internal/enforce"
	"github.com/looprig/sandbox/internal/policy"
)

// authorityRoutingBackend records which compile entry point a grant compile
// reached.
type authorityRoutingBackend struct {
	compiles          int
	authorityCompiles int
	gotAuthority      any
	gotHandles        int
}

func (b *authorityRoutingBackend) Compile(policy.Effective) (enforce.Spec, CompileReport, uint8, uint64, error) {
	b.compiles++
	return enforce.Spec{}, CompileReport{}, LevelNone, 0, nil
}

func (b *authorityRoutingBackend) CompileWithGrantAuthority(authority any, _, _ policy.Effective, handles []*policy.PathHandle) (enforce.Spec, CompileReport, uint8, uint64, error) {
	b.authorityCompiles++
	b.gotAuthority = authority
	b.gotHandles = len(handles)
	return enforce.Spec{}, CompileReport{}, LevelNone, 0, nil
}

// TestGrantCompileRoutesThroughAuthorityWithoutPathHandles pins the routing
// the first Windows CI run's facade failure needed: a command grant carries
// no path handles, and compileBackendWithGrantPaths used to send every
// handle-less grant to a full backend Compile — which for the Windows
// restricted tier tried to prepare a SECOND base lease for an executor that
// already held one ("restricted backend base lease is already active"). A
// backend that implements grantAuthorityBackend must receive every grant
// compile that has an authority, handles or not; one without an authority
// keeps the previous Compile path.
func TestGrantCompileRoutesThroughAuthorityWithoutPathHandles(t *testing.T) {
	authority := &struct{ name string }{"executor-authority"}
	backend := &authorityRoutingBackend{}
	if _, _, _, _, err := compileBackendWithGrantPaths(backend, authority, policy.Effective{}, policy.Effective{}, nil); err != nil {
		t.Fatal(err)
	}
	if backend.authorityCompiles != 1 || backend.compiles != 0 || backend.gotAuthority != authority || backend.gotHandles != 0 {
		t.Fatalf("handle-less grant compile = %+v, want exactly one authority compile carrying the executor's authority", backend)
	}

	unauthorized := &authorityRoutingBackend{}
	if _, _, _, _, err := compileBackendWithGrantPaths(unauthorized, nil, policy.Effective{}, policy.Effective{}, nil); err != nil {
		t.Fatal(err)
	}
	if unauthorized.compiles != 1 || unauthorized.authorityCompiles != 0 {
		t.Fatalf("grant compile with no authority = %+v, want the plain Compile path", unauthorized)
	}
}
