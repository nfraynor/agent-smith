package compose

import (
	"context"
	"reflect"
	"testing"
)

type fakeRunner struct {
	dir    string
	args   []string
	result CommandResult
	err    error
}

func (f *fakeRunner) Run(_ context.Context, dir string, args []string, _ int64) (CommandResult, error) {
	f.dir = dir
	f.args = append([]string(nil), args...)
	return f.result, f.err
}

func TestRejectsUnconfiguredAndInjectedNames(t *testing.T) {
	s, err := New([]Project{{Name: "app", Path: "/managed/app", File: "compose.yaml"}}, &fakeRunner{}, 1024)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ project, service string }{{"missing", "api"}, {"app; rm -rf /", "api"}, {"app", "api --profile evil"}} {
		if _, err = s.Restart(context.Background(), tc.project, tc.service); err == nil {
			t.Fatalf("expected rejection for %#v", tc)
		}
	}
}

func TestUpBuildsFixedArgumentVector(t *testing.T) {
	r := &fakeRunner{}
	s, err := New([]Project{{Name: "app", Path: "/managed/app", File: "compose.yaml"}}, r, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Up(context.Background(), "app", "api", true); err != nil {
		t.Fatal(err)
	}
	want := []string{"compose", "--project-name", "app", "--file", "/managed/app/compose.yaml", "up", "--detach", "--force-recreate", "api"}
	if !reflect.DeepEqual(r.args, want) {
		t.Fatalf("args=%q want=%q", r.args, want)
	}
}

func TestStatusAcceptsJSONLines(t *testing.T) {
	r := &fakeRunner{result: CommandResult{Stdout: "{\"Name\":\"app-api-1\",\"Service\":\"api\",\"State\":\"running\"}\n{\"Name\":\"app-db-1\",\"Service\":\"db\",\"State\":\"exited\"}\n"}}
	s, err := New([]Project{{Name: "app", Path: "/managed/app"}}, r, 1024)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Status(context.Background(), "app")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Service != "api" || got[1].State != "exited" {
		t.Fatalf("unexpected statuses: %#v", got)
	}
}
