package deployment

import (
	"context"
	"strings"
	"testing"
)

func TestDeployRejectsImageDifferentFromComposeConfiguration(t *testing.T) {
	compose := &fakeCompose{}
	service := New(compose, fakeDocker{}, fakeHealth{}, &fakeRecorder{}, Options{})
	result, err := service.Deploy(context.Background(), Request{Project: "app", Service: "api", Image: "api:new"})
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("result=%#v error=%v", result, err)
	}
	if len(compose.calls) != 0 {
		t.Fatalf("deployment mutated Compose after mismatch: %v", compose.calls)
	}
}
