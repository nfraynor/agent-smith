package godmode

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"
)

type fakeRunner struct {
	name string
	args []string
	env  []string
	out  []byte
	err  []byte
}

func (f *fakeRunner) Run(_ context.Context, name string, args, env []string) ([]byte, []byte, int, error) {
	f.name, f.args, f.env = name, args, env
	return f.out, f.err, 0, nil
}

func TestDisabledDoesNotExecute(t *testing.T) {
	fake := &fakeRunner{}
	_, err := (Runner{Enabled: false, CommandRunner: fake}).Execute(context.Background(), Request{Command: "id"})
	if err == nil || !strings.Contains(err.Error(), "GODMODE_DISABLED") {
		t.Fatalf("expected GODMODE_DISABLED, got %v", err)
	}
	if fake.name != "" {
		t.Fatal("disabled runner executed a command")
	}
}

func TestUsesHostNamespacesAndPositionalWorkingDirectory(t *testing.T) {
	fake := &fakeRunner{out: []byte("ok")}
	runner := Runner{Enabled: true, CommandRunner: fake, MaximumTimeout: time.Minute}
	result, err := runner.Execute(context.Background(), Request{
		Command:          "printf '%s' ok",
		WorkingDirectory: "/tmp/space and;metacharacters",
		Environment:      map[string]string{"ZED": "2", "ALPHA": "1"},
	})
	if err != nil || !result.Success || result.Stdout != "ok" {
		t.Fatalf("unexpected result %#v, error %v", result, err)
	}
	wantPrefix := []string{"--target", "1", "--mount", "--uts", "--ipc", "--net", "--pid", "--"}
	if !reflect.DeepEqual(fake.args[:len(wantPrefix)], wantPrefix) {
		t.Fatalf("nsenter arguments = %#v", fake.args)
	}
	if got := fake.args[len(fake.args)-2]; got != "/tmp/space and;metacharacters" {
		t.Fatalf("working directory argument = %q", got)
	}
	if !reflect.DeepEqual(fake.env, []string{"ALPHA=1", "ZED=2"}) {
		t.Fatalf("environment = %#v", fake.env)
	}
}

func TestRejectsInvalidEnvironmentAndBoundsCombinedOutput(t *testing.T) {
	fake := &fakeRunner{out: []byte("12345"), err: []byte("67890")}
	runner := Runner{Enabled: true, CommandRunner: fake, MaxOutputBytes: 7}
	if _, err := runner.Execute(context.Background(), Request{Command: "x", Environment: map[string]string{"BAD-NAME": "x"}}); err == nil {
		t.Fatal("expected invalid environment error")
	}
	result, err := runner.Execute(context.Background(), Request{Command: "x"})
	if err != nil || !result.Truncated || result.Stdout != "12345" || result.Stderr != "67" {
		t.Fatalf("unexpected bounded result %#v, error %v", result, err)
	}
}
