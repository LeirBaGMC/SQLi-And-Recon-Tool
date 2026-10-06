package policy

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDVWALevelPolicy(t *testing.T) {
	for _, level := range []string{"", "low", "medium", "Medium", "high", "High"} {
		target, err := ValidateTarget(TargetRequest{Mode: TargetModeDVWA, Target: "dvwa", DVWALevel: level})
		if err != nil {
			t.Fatal(err)
		}
		if strings.EqualFold(level, "medium") {
			if target.DVWALevel != "medium" || strings.Contains(target.URL, "?") || !strings.Contains(target.Name, "Medium") {
				t.Fatalf("incorrect Medium target: %+v", target)
			}
		} else if strings.EqualFold(level, "high") {
			if target.DVWALevel != "high" || strings.Contains(target.URL, "?") || !strings.Contains(target.Name, "High") {
				t.Fatalf("incorrect High target: %+v", target)
			}
		} else if target.DVWALevel != "low" {
			t.Fatalf("incorrect default level: %+v", target)
		}
	}
	for _, level := range []string{"impossible", "http://example.com"} {
		if _, err := ValidateTarget(TargetRequest{Mode: TargetModeDVWA, Target: "dvwa", DVWALevel: level}); err == nil {
			t.Fatalf("unsupported level accepted: %s", level)
		}
	}
}

func TestDVWAWorkerBoundsAndURLScope(t *testing.T) {
	for _, workers := range []int{0, 1, 2, 4} {
		target, err := ValidateTarget(TargetRequest{Mode: TargetModeDVWA, Target: "dvwa", Workers: workers})
		if err != nil || target.Workers < 1 {
			t.Fatalf("valid worker count rejected: %d %v", workers, err)
		}
	}
	for _, workers := range []int{-1, 3, 5, 100} {
		if _, err := ValidateTarget(TargetRequest{Mode: TargetModeDVWA, Target: "dvwa", Workers: workers}); err == nil {
			t.Fatalf("worker bound ignored: %d", workers)
		}
	}
	if _, err := ValidateTarget(TargetRequest{Mode: TargetModeAuthorizedURL, URL: "http://localhost/?id=1", AuthorizationConfirmed: true, Workers: 4}); err == nil {
		t.Fatal("URL mode silently ignored requested concurrency")
	}
}

func TestDVWAPreparedVariantUsesSameLevelAndParameter(t *testing.T) {
	for _, level := range []string{"low", "medium", "high"} {
		target, err := ValidateTarget(TargetRequest{Mode: TargetModeDVWA, Target: "dvwa", DVWALevel: level, DVWAVariant: "prepared", Workers: 2})
		if err != nil || !strings.Contains(target.URL, "/sqli-fixed/") || target.Parameter != "id" || target.DVWALevel != level || !strings.Contains(target.Name, "Corregido") {
			t.Fatalf("incorrect prepared target: %+v %v", target, err)
		}
	}
	if _, err := ValidateTarget(TargetRequest{Mode: TargetModeDVWA, Target: "dvwa", DVWAVariant: "http://example.com"}); err == nil {
		t.Fatal("arbitrary variant accepted")
	}
}

func TestDVWAIsTheOnlyLocalTarget(t *testing.T) {
	for _, mode := range []string{TargetModeDVWA, TargetModeSandbox} {
		target, err := ValidateTarget(TargetRequest{Mode: mode, Target: "dvwa", URL: "http://example.com"})
		if err != nil || target.Host != "dvwa" || target.Mode != TargetModeDVWA {
			t.Fatalf("unexpected DVWA policy: %+v %v", target, err)
		}
		for _, oldTarget := range []string{"vulnerable-app", "secure-app", "example.com"} {
			if _, err := ValidateTarget(TargetRequest{Mode: mode, Target: oldTarget}); err == nil {
				t.Fatalf("retired target accepted: %s", oldTarget)
			}
		}
	}
}

func TestURLTargetsAcceptDomainsIPsAndLocalHosts(t *testing.T) {
	t.Setenv("ALLOWED_EXTERNAL_HOSTS", "testphp.vulnweb.com")
	for _, rawURL := range []string{
		"https://example.com/products?id=2",
		"http://testasp.vulnweb.com/?id=1",
		"http://localhost:8000/?id=1",
		"http://127.0.0.1:8000/?id=1",
		"http://[::1]:8000/?id=1",
		"http://192.168.1.20:8080/?id=1",
		"http://host.docker.internal:8000/?id=1",
	} {
		target, err := ValidateTarget(TargetRequest{Mode: TargetModeAuthorizedURL, URL: rawURL, AuthorizationConfirmed: true})
		if err != nil || target.URL != rawURL || target.Host == "" || target.Parameter != "id" {
			t.Fatalf("valid URL rejected or changed: %s err=%v", rawURL, err)
		}
	}
}

func TestExternalCredentialsAndCustomPortsAreAllowedWithoutPersistingSecrets(t *testing.T) {
	for _, rawURL := range []string{"http://workshop-user:secret%40value@example.com:8080/?cat=1", "https://workshop-user:secret%40value@localhost:8443/?cat=1"} {
		target, err := ValidateTarget(TargetRequest{Mode: TargetModeAuthorizedURL, URL: rawURL, AuthorizationConfirmed: true})
		if err != nil {
			t.Fatal(err)
		}
		password, _ := target.BasicAuth.Password()
		if target.BasicAuth.Username() != "workshop-user" || password != "secret@value" || strings.Contains(target.URL, "@") || !strings.Contains(target.URL, ":8") {
			t.Fatal("credentials or custom port lost")
		}
		encoded, err := json.Marshal(target)
		if err != nil || strings.Contains(string(encoded), "workshop-user") || strings.Contains(string(encoded), "secret") {
			t.Fatal("target serialization exposed credentials")
		}
	}
}

func TestRejectsMissingAuthorization(t *testing.T) {
	if _, err := ValidateTarget(TargetRequest{Mode: TargetModeAuthorizedURL, URL: "http://localhost:8000/?id=1"}); err == nil {
		t.Fatal("missing authorization accepted")
	}
}

func TestAllowsURLWithoutParameterForDiscovery(t *testing.T) {
	target, err := ValidateTarget(TargetRequest{Mode: TargetModeAuthorizedURL, URL: "https://example.com/", AuthorizationConfirmed: true})
	if err != nil || target.Parameter != "" {
		t.Fatalf("unexpected discovery target: %+v err=%v", target, err)
	}
}

func TestRejectsMalformedOrNonHTTPURL(t *testing.T) {
	for _, rawURL := range []string{"", "/products?id=1", "ftp://example.com/file", "file:///tmp/test", "http://", "http://example.com:invalid/"} {
		if _, err := ValidateTarget(TargetRequest{Mode: TargetModeAuthorizedURL, URL: rawURL, AuthorizationConfirmed: true}); err == nil {
			t.Fatalf("invalid URL accepted: %s", rawURL)
		}
	}
}
