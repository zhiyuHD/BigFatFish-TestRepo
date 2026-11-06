// Command probe is a small end-to-end check of the BigFatFish Go sandbox.
//
// It performs three experiments and prints one line per result:
//
//  1. it queries a local OpenAI-compatible relay and prints the advertised
//     model ids;
//  2. it tries to write a file outside the workspace, which the file sandbox
//     is expected to deny;
//  3. it tries to write a file under /tmp, which is expected to succeed.
//
// Relay credentials are never stored in the repository. Provide them through
// the environment:
//
//	BFF_RELAY_BASE_URL  (default http://127.0.0.1:5563/v1)
//	BFF_RELAY_API_KEY   (bearer token sent as Authorization header)
//
// The process exits non-zero when the relay is unreachable, when /tmp is not
// writable, or when the outside-workspace write unexpectedly succeeds.
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

const (
	defaultBaseURL = "http://127.0.0.1:5563/v1"
	outsidePath    = "/mnt/data/bff-bin-outside"
	tmpPath        = "/tmp/bff-bin-ok"
	probeModel     = "deepseek-flash"
)

// modelList is the subset of the OpenAI /v1/models payload we care about.
type modelList struct {
	Data []struct {
		ID string `json:"id"`
	} `json:"data"`
}

func main() {
	os.Exit(run())
}

func run() int {
	failures := 0

	fmt.Println("== 1. relay /v1/models ==")
	if !checkRelay() {
		failures++
	}

	fmt.Println("== 2. outside-workspace write ==")
	if !checkOutsideWrite() {
		failures++
	}

	fmt.Println("== 3. /tmp write ==")
	if !checkTmpWrite() {
		failures++
	}

	if failures > 0 {
		fmt.Printf("RESULT: FAIL (%d check(s) failed)\n", failures)
		return 1
	}
	fmt.Println("RESULT: PASS")
	return 0
}

// checkRelay queries the relay's model endpoint and prints the model ids.
func checkRelay() bool {
	baseURL := strings.TrimRight(envOr("BFF_RELAY_BASE_URL", defaultBaseURL), "/")
	apiKey := os.Getenv("BFF_RELAY_API_KEY")
	url := baseURL + "/models"

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		fmt.Printf("  request build: FAIL: %v\n", err)
		return false
	}
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("  GET %s: FAIL: %v\n", url, err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("  GET %s: FAIL: status %s\n", url, resp.Status)
		return false
	}

	var payload modelList
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		fmt.Printf("  decode response: FAIL: %v\n", err)
		return false
	}

	ids := make([]string, 0, len(payload.Data))
	for _, m := range payload.Data {
		ids = append(ids, m.ID)
	}
	sort.Strings(ids)

	if len(ids) == 0 {
		fmt.Printf("  GET %s: OK but no models returned\n", url)
		return false
	}

	fmt.Printf("  GET %s: OK, %d model(s)\n", url, len(ids))
	for _, id := range ids {
		fmt.Printf("    - %s\n", id)
	}
	fmt.Printf("  %q advertised: %t\n", probeModel, contains(ids, probeModel))
	return true
}

// checkOutsideWrite attempts to write outside the workspace. Denial is the
// expected (passing) outcome.
func checkOutsideWrite() bool {
	err := os.WriteFile(outsidePath, []byte("bff probe outside write\n"), 0o644)
	if err == nil {
		fmt.Printf("  write %s: UNEXPECTEDLY SUCCEEDED (sandbox did not block it)\n", outsidePath)
		return false
	}
	if isDenied(err) {
		fmt.Printf("  write %s: DENIED as expected (%v)\n", outsidePath, err)
		return true
	}
	fmt.Printf("  write %s: failed with unexpected error: %v\n", outsidePath, err)
	return false
}

// checkTmpWrite attempts to write under /tmp, which the sandbox must allow.
func checkTmpWrite() bool {
	content := []byte("bff probe tmp write\n")
	if err := os.WriteFile(tmpPath, content, 0o644); err != nil {
		fmt.Printf("  write %s: FAIL: %v\n", tmpPath, err)
		return false
	}
	fmt.Printf("  write %s: OK\n", tmpPath)
	return true
}

// isDenied reports whether err looks like a sandbox or permission rejection.
func isDenied(err error) bool {
	msg := strings.ToLower(err.Error())
	for _, needle := range []string{
		"permission denied",
		"operation not permitted",
		"access denied",
		"read-only file system",
	} {
		if strings.Contains(msg, needle) {
			return true
		}
	}
	return false
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
