package sandbox

// nullBackend is the fallback backend: it applies no OS-level enforcement. It
// exists so the executor has a working, honest backend on every platform before
// the real ones land, and so a platform with no available mechanism degrades to
// "no isolation" rather than failing to construct. Its compiled spawnSpec is a
// pure passthrough — commands run exactly as a plain os/exec would — so the only
// property the executor can still guarantee is env scrubbing, which the executor
// performs itself.
type nullBackend struct{}

// newNullBackend returns the singleton-shaped null backend. It is stateless, so
// a fresh value per call is fine.
func newNullBackend() *nullBackend { return &nullBackend{} }

// compile returns a passthrough spawnSpec and the honest null posture: no OS
// enforcement (LevelNone), an empty report (nothing was enforced OR narrowed —
// the null backend does not attempt any feature, so there is nothing to record),
// and GuaranteeEnvScrub as the only guarantee bit it can set — but ONLY when the
// policy actually scrubs the environment (!Env.Inherit). Env scrubbing holds
// independently of any OS backend because the executor assembles the child
// environment from the EnvPolicy regardless of mechanism; but an Env.Inherit
// (unconfined) policy passes the whole parent environment through, so nothing is
// scrubbed and claiming EnvScrub would be dishonest — guaranteeBits is then 0.
// Every other guarantee stays false (fail-closed) because nothing else is enforced.
func (nullBackend) compile(p Policy) (spawnSpec, CompileReport, uint8, uint64, error) {
	spec := spawnSpec{
		wrapShell: func(command string) []string { return []string{"/bin/sh", "-c", command} },
		wrapArgv:  func(argv []string) []string { return argv },
		configure: nil,
	}
	var bits uint64
	if !p.Env.Inherit {
		bits = GuaranteeEnvScrub
	}
	return spec, CompileReport{}, LevelNone, bits, nil
}

// platformBackend selects the backend for the current platform. Today the null
// backend is the only one, so there is intentionally no build-tag dispatch yet.
//
// TODO(Task 8/10): build-tag per-platform selection (Seatbelt/Linux ladder)
// replaces this — a darwin file returns the Seatbelt backend, a linux file
// probes the namespace/Landlock ladder, and this fallback is used only where no
// mechanism is available. The future windows selector must fail with
// ErrUnsupportedPlatform (SPEC §7.3) BEFORE reaching the null backend: null's
// spawnSpec execs the Unix "/bin/sh", which is not a valid Windows fallback, so
// null must never be selected on Windows.
func platformBackend() backend { return newNullBackend() }
