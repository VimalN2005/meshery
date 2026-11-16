// Copyright Meshery Authors
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

package system

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/meshery/meshery/mesheryctl/pkg/utils"
	"github.com/spf13/viper"
)

// TestLoginCmdArgs pins the argument validator of `system login`:
// the command takes no positional arguments, so any supplied argument
// must be rejected before the login handler runs.
func TestLoginCmdArgs(t *testing.T) {
	if err := loginCmd.Args(loginCmd, []string{"unexpected-arg"}); err == nil {
		t.Error("expected an error when passing a positional argument to 'system login', got nil")
	}
	if err := loginCmd.Args(loginCmd, []string{"unexpected-arg-1", "unexpected-arg-2"}); err == nil {
		t.Error("expected an error when passing multiple positional arguments to 'system login', got nil")
	}
	if err := loginCmd.Args(loginCmd, []string{}); err != nil {
		t.Errorf("expected no error when passing no arguments to 'system login', got %v", err)
	}
}

// TestLoginCmdFlags verifies that the provider flag remains registered
// and supported by loginCmd and is not affected by argument validation changes.
func TestLoginCmdFlags(t *testing.T) {
	flag := loginCmd.PersistentFlags().Lookup("provider")
	if flag == nil {
		t.Fatal("expected 'provider' flag to be registered on loginCmd, got nil")
	}
	if flag.Shorthand != "p" {
		t.Errorf("expected shorthand for 'provider' flag to be 'p', got %q", flag.Shorthand)
	}
}

// TestLoginCmd_ServerUnavailableError verifies that when the Meshery Server
// endpoint is unreachable, `system login` returns a descriptive message with
// the server URL and remediation prompt rather than a platform connection failure (#11420).
func TestLoginCmd_ServerUnavailableError(t *testing.T) {
	setupContextTestEnv(t)
	utils.SetupMeshkitLoggerTesting(t, false)

	unreachableURL := "http://127.0.0.1:54321"
	viper.Set("contexts.local.platform", "kubernetes")
	viper.Set("contexts.local.endpoint", unreachableURL)
	if err := viper.WriteConfig(); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	err := loginCmd.RunE(loginCmd, []string{})
	if err == nil {
		t.Fatal("expected error when server is unreachable, got nil")
	}

	errMsg := err.Error()
	if !strings.Contains(errMsg, fmt.Sprintf("Meshery Server unavailable at %s", unreachableURL)) {
		t.Errorf("expected error message to contain server URL %q, got: %s", unreachableURL, errMsg)
	}
	if !strings.Contains(errMsg, "Is your Meshery Server up and running?") {
		t.Errorf("expected error message to contain 'Is your Meshery Server up and running?', got: %s", errMsg)
	}
	if strings.Contains(errMsg, "failed to check Meshery Server status") {
		t.Errorf("expected error not to include platform check status error, got: %s", errMsg)
	}
}

// TestLoginCmd_SuccessfulLoginDoesNotRequirePlatformConnection verifies that
// `system login` authenticates via HTTP without requiring an active connection to
// the underlying platform orchestrator (e.g. Kubernetes cluster API) (#11420).
func TestLoginCmd_SuccessfulLoginDoesNotRequirePlatformConnection(t *testing.T) {
	setupContextTestEnv(t)
	utils.SetupMeshkitLoggerTesting(t, false)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/providers":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]utils.Provider{
				"None": {
					ProviderName: "None",
					ProviderType: "local",
					ProviderURL:  "",
				},
			})
		case "/api/user/token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"token":"test-token"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	// Platform explicitly set to kubernetes, simulating an environment without an active cluster
	viper.Set("contexts.local.platform", "kubernetes")
	viper.Set("contexts.local.endpoint", ts.URL)
	tempDir := t.TempDir()
	viper.Set("tokens", []map[string]string{
		{"name": "default", "location": filepath.Join(tempDir, "auth.json")},
	})
	if err := viper.WriteConfig(); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	systemLoginFlags.Provider = "None"
	defer func() { systemLoginFlags.Provider = "" }()

	if err := loginCmd.RunE(loginCmd, []string{}); err != nil {
		t.Fatalf("expected login to succeed without platform connection, got: %v", err)
	}

	tokenFile := filepath.Join(tempDir, "auth.json")
	if _, err := os.Stat(tokenFile); os.IsNotExist(err) {
		t.Errorf("expected token file %s to be created", tokenFile)
	}
}
