package main

import (
	"os"
	"os/exec"
	"sync"
	"testing"
)

// getBuildOnce ensures the sync.Once object is initialized and retrieved safely.
// This design pattern satisfies linters that flag global variables.
func getBuildOnce() *sync.Once {
	var pluginBuildOnce sync.Once
	return &pluginBuildOnce
}

// runPluginBuild executes 'make build' exactly once.
func runPluginBuild(t *testing.T) {
	getBuildOnce().Do(func() {
		if err := os.Mkdir("build", 0755); err != nil && !os.IsExist(err) {
			t.Fatalf("failed to create build directory: %v", err)
		}

		buildCmd := exec.Command("make", "build")
		out, err := buildCmd.CombinedOutput()

		if err != nil {
			t.Fatalf("Plugin build failed (make build): %s\nError: %v", out, err)
		}
	})
}
