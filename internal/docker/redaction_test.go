package docker

import (
	"reflect"
	"testing"
)

func TestRedactEnvironment(t *testing.T) {
	got := redactEnvironment([]string{"NORMAL=visible", "API_TOKEN=secret", "PASSWORD=hunter2", "FLAG"})
	want := []string{"NORMAL=visible", "API_TOKEN=[REDACTED]", "PASSWORD=[REDACTED]", "FLAG"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q want %q", got, want)
	}
}
