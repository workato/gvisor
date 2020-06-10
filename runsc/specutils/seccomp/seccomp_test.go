// Copyright 2020 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package seccomp

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"syscall"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	seccomp "github.com/seccomp/libseccomp-golang"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/binary"
	"gvisor.dev/gvisor/pkg/bpf"
	"gvisor.dev/gvisor/pkg/usermem"
)

type seccompData struct {
	nr                 uint32
	arch               uint32
	instructionPointer uint64
	args               [6]uint64
}

// asInput converts a seccompData to a bpf.Input.
func asInput(d seccompData) bpf.Input {
	return bpf.InputBytes{binary.Marshal(nil, binary.LittleEndian, d), binary.LittleEndian}
}

// testInput creates an Input struct with given seccomp input values.
func testInput(arch uint32, syscallName string, args *[6]uint64) bpf.Input {
	syscallNo, err := lookupSyscallNo(arch, syscallName)
	if err != nil {
		// Assume tests set valid syscall names.
		panic(err)
	}

	if args == nil {
		argArray := [6]uint64{0, 0, 0, 0, 0, 0}
		args = &argArray
	}

	data := seccompData{
		nr:   syscallNo,
		arch: arch,
		args: *args,
	}

	return asInput(data)
}

// testCase holds a seccomp test case.
type testCase struct {
	name     string
	config   specs.LinuxSeccomp
	input    bpf.Input
	expected uint32
}

var (
	// seccompTests is a list of speccomp test cases.
	seccompTests = []testCase{
		{
			name: "default_allow",
			config: specs.LinuxSeccomp{
				DefaultAction: specs.ActAllow,
			},
			input:    testInput(nativeArchAuditNo, "read", nil),
			expected: uint32(allowAction),
		},
		{
			name: "default_deny",
			config: specs.LinuxSeccomp{
				DefaultAction: specs.ActErrno,
			},
			input:    testInput(nativeArchAuditNo, "read", nil),
			expected: uint32(errnoAction),
		},
		{
			name: "deny_arch",
			config: specs.LinuxSeccomp{
				DefaultAction: specs.ActAllow,
				Syscalls: []specs.LinuxSyscall{
					{
						Names: []string{
							"getcwd",
						},
						Action: specs.ActErrno,
					},
				},
			},
			// Syscall matches but the arch is AUDIT_ARCH_X86 so the return
			// value is the bad arch action.
			input:    asInput(seccompData{nr: 183, arch: 0x40000003}), //
			expected: uint32(killThreadAction),
		},
		{
			name: "match_name_errno",
			config: specs.LinuxSeccomp{
				DefaultAction: specs.ActAllow,
				Syscalls: []specs.LinuxSyscall{
					{
						Names: []string{
							"getcwd",
							"chmod",
						},
						Action: specs.ActErrno,
					},
					{
						Names: []string{
							"write",
						},
						Action: specs.ActTrace,
					},
				},
			},
			input:    testInput(nativeArchAuditNo, "getcwd", nil),
			expected: uint32(errnoAction),
		},
		{
			name: "match_name_trace",
			config: specs.LinuxSeccomp{
				DefaultAction: specs.ActAllow,
				Syscalls: []specs.LinuxSyscall{
					{
						Names: []string{
							"getcwd",
							"chmod",
						},
						Action: specs.ActErrno,
					},
					{
						Names: []string{
							"write",
						},
						Action: specs.ActTrace,
					},
				},
			},
			input:    testInput(nativeArchAuditNo, "write", nil),
			expected: uint32(traceAction),
		},
		{
			name: "no_match_name_allow",
			config: specs.LinuxSeccomp{
				DefaultAction: specs.ActAllow,
				Syscalls: []specs.LinuxSyscall{
					{
						Names: []string{
							"getcwd",
							"chmod",
						},
						Action: specs.ActErrno,
					},
					{
						Names: []string{
							"write",
						},
						Action: specs.ActTrace,
					},
				},
			},
			input:    testInput(nativeArchAuditNo, "open", nil),
			expected: uint32(allowAction),
		},
		{
			name: "simple_match_args",
			config: specs.LinuxSeccomp{
				DefaultAction: specs.ActAllow,
				Syscalls: []specs.LinuxSyscall{
					{
						Names: []string{
							"clone",
						},
						Args: []specs.LinuxSeccompArg{
							{
								Index: 0,
								Value: syscall.CLONE_FS,
								Op:    specs.OpEqualTo,
							},
						},
						Action: specs.ActErrno,
					},
				},
			},
			input:    testInput(nativeArchAuditNo, "clone", &[6]uint64{syscall.CLONE_FS}),
			expected: uint32(errnoAction),
		},
		{
			name: "match_args_or",
			config: specs.LinuxSeccomp{
				DefaultAction: specs.ActAllow,
				Syscalls: []specs.LinuxSyscall{
					{
						Names: []string{
							"clone",
						},
						Args: []specs.LinuxSeccompArg{
							{
								Index: 0,
								Value: syscall.CLONE_FS,
								Op:    specs.OpEqualTo,
							},
							{
								Index: 0,
								Value: syscall.CLONE_VM,
								Op:    specs.OpEqualTo,
							},
						},
						Action: specs.ActErrno,
					},
				},
			},
			input:    testInput(nativeArchAuditNo, "clone", &[6]uint64{syscall.CLONE_FS}),
			expected: uint32(errnoAction),
		},
		{
			name: "match_args_and",
			config: specs.LinuxSeccomp{
				DefaultAction: specs.ActAllow,
				Syscalls: []specs.LinuxSyscall{
					{
						Names: []string{
							"getsockopt",
						},
						Args: []specs.LinuxSeccompArg{
							{
								Index: 1,
								Value: syscall.SOL_SOCKET,
								Op:    specs.OpEqualTo,
							},
							{
								Index: 2,
								Value: syscall.SO_PEERCRED,
								Op:    specs.OpEqualTo,
							},
						},
						Action: specs.ActErrno,
					},
				},
			},
			input:    testInput(nativeArchAuditNo, "getsockopt", &[6]uint64{0, syscall.SOL_SOCKET, syscall.SO_PEERCRED}),
			expected: uint32(errnoAction),
		},
		{
			name: "no_match_args_and",
			config: specs.LinuxSeccomp{
				DefaultAction: specs.ActAllow,
				Syscalls: []specs.LinuxSyscall{
					{
						Names: []string{
							"getsockopt",
						},
						Args: []specs.LinuxSeccompArg{
							{
								Index: 1,
								Value: syscall.SOL_SOCKET,
								Op:    specs.OpEqualTo,
							},
							{
								Index: 2,
								Value: syscall.SO_PEERCRED,
								Op:    specs.OpEqualTo,
							},
						},
						Action: specs.ActErrno,
					},
				},
			},
			input:    testInput(nativeArchAuditNo, "getsockopt", &[6]uint64{0, syscall.SOL_SOCKET}),
			expected: uint32(allowAction),
		},
		{
			name: "Simple args (no match)",
			config: specs.LinuxSeccomp{
				DefaultAction: specs.ActAllow,
				Syscalls: []specs.LinuxSyscall{
					{
						Names: []string{
							"clone",
						},
						Args: []specs.LinuxSeccompArg{
							{
								Index: 0,
								Value: syscall.CLONE_FS,
								Op:    specs.OpEqualTo,
							},
						},
						Action: specs.ActErrno,
					},
				},
			},
			input:    testInput(nativeArchAuditNo, "clone", &[6]uint64{syscall.CLONE_VM}),
			expected: uint32(allowAction),
		},
		{
			name: "OpMaskedEqual (match)",
			config: specs.LinuxSeccomp{
				DefaultAction: specs.ActAllow,
				Syscalls: []specs.LinuxSyscall{
					{
						Names: []string{
							"clone",
						},
						Args: []specs.LinuxSeccompArg{
							{
								Index:    0,
								Value:    syscall.CLONE_FS,
								ValueTwo: syscall.CLONE_FS,
								Op:       specs.OpMaskedEqual,
							},
						},
						Action: specs.ActErrno,
					},
				},
			},
			input:    testInput(nativeArchAuditNo, "clone", &[6]uint64{syscall.CLONE_FS | syscall.CLONE_VM}),
			expected: uint32(errnoAction),
		},
		{
			name: "OpMaskedEqual (no match)",
			config: specs.LinuxSeccomp{
				DefaultAction: specs.ActAllow,
				Syscalls: []specs.LinuxSyscall{
					{
						Names: []string{
							"clone",
						},
						Args: []specs.LinuxSeccompArg{
							{
								Index:    0,
								Value:    syscall.CLONE_FS | syscall.CLONE_VM,
								ValueTwo: syscall.CLONE_FS | syscall.CLONE_VM,
								Op:       specs.OpMaskedEqual,
							},
						},
						Action: specs.ActErrno,
					},
				},
			},
			input:    testInput(nativeArchAuditNo, "clone", &[6]uint64{syscall.CLONE_FS}),
			expected: uint32(allowAction),
		},
		{
			name: "OpMaskedEqual (clone)",
			config: specs.LinuxSeccomp{
				DefaultAction: specs.ActErrno,
				Syscalls: []specs.LinuxSyscall{
					{
						Names: []string{
							"clone",
						},
						// This comes from the Docker default seccomp
						// profile for clone.
						Args: []specs.LinuxSeccompArg{
							{
								Index:    0,
								Value:    0x7e020000,
								ValueTwo: 0x0,
								Op:       specs.OpMaskedEqual,
							},
						},
						Action: specs.ActAllow,
					},
				},
			},
			input:    testInput(nativeArchAuditNo, "clone", &[6]uint64{0x50f00}),
			expected: uint32(allowAction),
		},
	}
)

// TestRunscSeccomp generates seccomp programs from OCI config and executes
// them using runsc's library, comparing against expected results.
func TestRunscSeccomp(t *testing.T) {
	for _, tc := range seccompTests {
		t.Run(tc.name, func(t *testing.T) {
			runscProgram, err := BuildProgram(&tc.config)
			if err != nil {
				t.Fatalf("generating runsc BPF: %v", err)
			}

			if err := checkProgram(runscProgram, tc.input, tc.expected); err != nil {
				t.Fatalf("running runsc BPF: %v", err)
			}
		})
	}
}

// TestLibSeccomp generates seccomp programs from OCI config using
// LibSeccomp-golang and executes them comparing against the expected results of
// the same test cases as those run against runsc's implementation. This helps
// ensure that runsc's OCI seccomp behavior is as close to that of runc as
// possible.
func TestLibSeccomp(t *testing.T) {
	for _, tc := range seccompTests {
		t.Run(tc.name, func(t *testing.T) {
			insts, err := getLibSeccompBPF(&tc.config)
			if err != nil {
				t.Fatalf("generating libseccomp BPF: %v", err)
			}

			p, err := bpf.Compile(insts)
			if err != nil {
				t.Fatalf("compiling libseccomp BPF: %v", err)
			}

			if err := checkProgram(p, tc.input, tc.expected); err != nil {
				t.Fatalf("running libseccomp BPF: %v", err)
			}
		})
	}
}

// checkProgram runs the given program over the given input and checks the
// result against the expected output.
func checkProgram(p bpf.Program, in bpf.Input, expected uint32) error {
	result, err := bpf.Exec(p, in)
	if err != nil {
		return err
	}

	if result != expected {
		// Include a decoded version of the program in output for debugging purposes.
		decoded, _ := bpf.DecodeProgram(p)
		return fmt.Errorf("Unexpected result: got: %d, expected: %d\nBPF Program\n%s", result, expected, decoded)
	}

	return nil
}

// getLibSeccompBPF generates seccomp BPF program based on OCI config using
// LibSeccomp and returns it as a list of BPFInstruction.
func getLibSeccompBPF(config *specs.LinuxSeccomp) ([]linux.BPFInstruction, error) {
	filter, err := genFilter(config)
	if err != nil {
		return nil, err
	}

	f, err := ioutil.TempFile("", "libseccomp")
	if err != nil {
		return nil, fmt.Errorf("creating temp file: %w", err)
	}
	defer os.Remove(f.Name())

	if err := filter.ExportBPF(f); err != nil {
		return nil, fmt.Errorf("exporting BPF: %w", err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}

	buf, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("reading temp file: %w", err)
	}

	// Sanity check on the program length. Each program should
	// be a list of 8 byte instructions.
	if len(buf)%8 != 0 {
		return nil, fmt.Errorf("unexpected buffer length: %d", len(buf))
	}

	// Allocate a slice with the size of the program. This size must be set
	// correctly for binary.Unmarshal to work.
	program := make([]linux.BPFInstruction, len(buf)/8)

	// Read the exported bpf program into an instruction list.
	// The program will be encoded in the endianness of the system where the
	// test is run. Use usermem.ByteOrder as a proxy for the host's
	// endianness.
	binary.Unmarshal(buf, usermem.ByteOrder, program)

	return program, nil
}

// genFilter converts OCI seccomp config into a libseccomp.ScmpFilter. This
// logic should closely resemble runc.
// See InitSeccomp in github.com/opencontainers/runc/libcontainer/seccomp/seccomp_linux.go
func genFilter(config *specs.LinuxSeccomp) (*seccomp.ScmpFilter, error) {
	defaultAction, err := convertScmpAction(config.DefaultAction)
	if err != nil {
		return nil, fmt.Errorf("invalid default action")
	}

	filter, err := seccomp.NewFilter(defaultAction)
	if err != nil {
		return nil, fmt.Errorf("creating filter: %s", err)
	}

	// Add extra architectures
	for _, arch := range config.Architectures {
		arch, err := convertScmpArch(arch)
		if err != nil {
			return nil, err
		}

		scmpArch, err := seccomp.GetArchFromString(arch)
		if err != nil {
			return nil, fmt.Errorf("invalid architecture: %s", err)
		}

		if err := filter.AddArch(scmpArch); err != nil {
			return nil, fmt.Errorf("adding arch to seccomp filter: %s", err)
		}
	}

	// Unset no new privs bit
	if err := filter.SetNoNewPrivsBit(false); err != nil {
		return nil, fmt.Errorf("setting no new privs: %s", err)
	}

	// Add a rule for each syscall
	for _, call := range config.Syscalls {
		if err = addSyscallRules(filter, call); err != nil {
			return nil, err
		}
	}

	return filter, nil
}

// addSyscallRules adds rules to match a single syscall rule to a filter. This
// logic should closely resemble runc.
// See matchCall in github.com/opencontainers/runc/libcontainer/seccomp/seccomp_linux.go
func addSyscallRules(filter *seccomp.ScmpFilter, call specs.LinuxSyscall) error {
	// If we can't resolve the syscall, assume it's not supported on this kernel
	// Ignore it, don't error out
	for _, name := range call.Names {
		callNum, err := seccomp.GetSyscallFromName(name)
		if err != nil {
			return nil
		}

		// Convert the call's action to the libseccomp equivalent
		callAct, err := convertScmpAction(call.Action)
		if err != nil {
			return fmt.Errorf("action in seccomp profile is invalid: %s", err)
		}

		// Unconditional match - just add the rule
		if len(call.Args) == 0 {
			if err = filter.AddRule(callNum, callAct); err != nil {
				return fmt.Errorf("adding seccomp filter rule for syscall %s: %s", name, err)
			}
		} else {
			// If two or more arguments have the same condition,
			// Revert to old behavior, adding each condition as a separate rule

			// Linux system calls can have at most 6 arguments
			argCounts := make([]uint, 6)
			conditions := []seccomp.ScmpCondition{}

			for _, cond := range call.Args {
				newCond, err := convertScmpCondition(cond)
				if err != nil {
					return fmt.Errorf("creating seccomp syscall condition for syscall %s: %s", name, err)
				}

				argCounts[cond.Index]++

				conditions = append(conditions, newCond)
			}

			hasMultipleArgs := false
			for _, count := range argCounts {
				if count > 1 {
					hasMultipleArgs = true
					break
				}
			}

			if hasMultipleArgs {
				// Revert to old behavior
				// Add each condition attached to a separate rule
				for _, cond := range conditions {
					condArr := []seccomp.ScmpCondition{cond}

					if err = filter.AddRuleConditional(callNum, callAct, condArr); err != nil {
						return fmt.Errorf("error adding seccomp rule for syscall %s: %s", name, err)
					}
				}
			} else {
				// No conditions share same argument
				// Use new, proper behavior
				if err = filter.AddRuleConditional(callNum, callAct, conditions); err != nil {
					return fmt.Errorf("error adding seccomp rule for syscall %s: %s", name, err)
				}
			}
		}
	}

	return nil
}

// convertScmpArch converts an architecture string into the string recognized
// by libseccomp.
func convertScmpArch(arch specs.Arch) (string, error) {
	switch arch {
	case specs.ArchX86:
		return "x86", nil
	case specs.ArchX86_64:
		return "amd64", nil
	case specs.ArchX32:
		return "x32", nil
	case specs.ArchARM:
		return "arm", nil
	case specs.ArchAARCH64:
		return "arm64", nil
	case specs.ArchMIPS:
		return "mips", nil
	case specs.ArchMIPS64:
		return "mips64", nil
	case specs.ArchMIPS64N32:
		return "mips64n32", nil
	case specs.ArchMIPSEL:
		return "mipsel", nil
	case specs.ArchMIPSEL64:
		return "mipsel64", nil
	case specs.ArchMIPSEL64N32:
		return "mipsel64n32", nil
	case specs.ArchPPC:
		return "ppc", nil
	case specs.ArchPPC64:
		return "ppc64", nil
	case specs.ArchPPC64LE:
		return "ppc64le", nil
	case specs.ArchS390:
		return "s390", nil
	case specs.ArchS390X:
		return "s390x", nil
	}
	return "", fmt.Errorf("invalid architecture: %s", arch)
}

// convertScmpAction converts a LinuxSeccompAction to libseccomp.ScmpAction.
func convertScmpAction(act specs.LinuxSeccompAction) (seccomp.ScmpAction, error) {
	switch act {
	case specs.ActKill:
		return seccomp.ActKill, nil
	case specs.ActTrap:
		return seccomp.ActTrap, nil
	case specs.ActErrno:
		return seccomp.ActErrno.SetReturnCode(int16(syscall.EPERM)), nil
	case specs.ActTrace:
		return seccomp.ActTrace.SetReturnCode(int16(syscall.EPERM)), nil
	case specs.ActAllow:
		return seccomp.ActAllow, nil
	// TODO(gvisor.dev/issue/3124): Support ActKillProcess and ActLog.
	// NOTE: specs packages does not support an ActKillThread
	default:
		return seccomp.ActInvalid, fmt.Errorf("invalid action, cannot use in rule")
	}
}

// convertScmpOperator converts an LinuxSeccompOperator to libseccomp.ScmpCompareOp.
func convertScmpOperator(op specs.LinuxSeccompOperator) (seccomp.ScmpCompareOp, error) {
	switch op {
	case specs.OpNotEqual:
		return seccomp.CompareNotEqual, nil
	case specs.OpLessThan:
		return seccomp.CompareLess, nil
	case specs.OpLessEqual:
		return seccomp.CompareLessOrEqual, nil
	case specs.OpEqualTo:
		return seccomp.CompareEqual, nil
	case specs.OpGreaterEqual:
		return seccomp.CompareGreaterEqual, nil
	case specs.OpGreaterThan:
		return seccomp.CompareGreater, nil
	case specs.OpMaskedEqual:
		return seccomp.CompareMaskedEqual, nil
	default:
		return seccomp.CompareInvalid, fmt.Errorf("invalid operator, cannot use in rule")
	}
}

// convertScmpCondition converts an Arg to libseccomp.ScmpCondition.
func convertScmpCondition(arg specs.LinuxSeccompArg) (seccomp.ScmpCondition, error) {
	cond := seccomp.ScmpCondition{}

	op, err := convertScmpOperator(arg.Op)
	if err != nil {
		return cond, err
	}

	return seccomp.MakeCondition(arg.Index, op, arg.Value, arg.ValueTwo)
}
