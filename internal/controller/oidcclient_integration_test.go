// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	havenv1 "github.com/zyvorai/haven/api/v1alpha1"
	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/native"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestOIDCClientAgainstRealHavenIdP runs the reconciler against a real
// `haven-idp dev` process (in-memory store, loopback only) through the native
// Admin API client, with a fake Kubernetes client. It is skipped unless
// HAVEN_IDP_INTEGRATION=1 because it compiles the binary (about a minute cold):
//
//	HAVEN_IDP_INTEGRATION=1 go test -run RealHavenIdP ./internal/controller
//
// The child gets a throwaway HOME / XDG_CONFIG_HOME so it never touches the
// developer's own dev credentials, and it is stopped by the PID this test
// started.
func TestOIDCClientAgainstRealHavenIdP(t *testing.T) {
	if os.Getenv("HAVEN_IDP_INTEGRATION") != "1" {
		t.Skip("set HAVEN_IDP_INTEGRATION=1 to build and run haven-idp dev")
	}
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "haven-idp")
	build := exec.Command("go", "build", "-o", bin, "./cmd/haven-idp")
	build.Dir = filepath.Join("..", "..")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build haven-idp: %v\n%s", err, out)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	home := filepath.Join(tmp, "home")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd := exec.Command(bin, "dev", "--port", fmt.Sprint(port), "--realm", "demo")
	cmd.Env = append(os.Environ(), "HOME="+home, "XDG_CONFIG_HOME="+filepath.Join(home, ".config"))
	cmd.Stdout, cmd.Stderr = io.Discard, &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := cmd.Process.Pid // the one process this test started
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	t.Cleanup(func() {
		select {
		case <-done:
			return
		default:
		}
		if p, err := os.FindProcess(pid); err == nil && pid == cmd.Process.Pid {
			_ = p.Signal(syscall.SIGTERM)
		}
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	})

	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	deadline := time.Now().Add(30 * time.Second)
	for {
		resp, err := http.Get(base + "/realms/demo/.well-known/openid-configuration")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				break
			}
		}
		select {
		case <-done:
			t.Fatalf("haven-idp dev exited early: %s", stderr.String())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("haven-idp dev not ready: %s", stderr.String())
		}
		time.Sleep(200 * time.Millisecond)
	}

	var adminSecret string
	filepath.Walk(home, func(p string, info os.FileInfo, err error) error { //nolint:errcheck
		if err == nil && !info.IsDir() && info.Name() == "dev.json" {
			var c struct{ AdminSecret string }
			if b, rerr := os.ReadFile(p); rerr == nil && json.Unmarshal(b, &c) == nil {
				adminSecret = c.AdminSecret
			}
		}
		return nil
	})
	if adminSecret == "" {
		t.Fatal("dev credentials not found in the throwaway home")
	}
	admin := native.New(native.Config{BaseURL: base, Realm: "demo", ClientID: "haven-admin", ClientSecret: adminSecret})

	plane := readyPlane("identity", allowApps, func(p *havenv1.IdentityPlane) { p.Spec.Bootstrap.FirstRealm = "demo" })
	job := &havenv1.OIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "job", Namespace: "apps", Generation: 1},
		Spec: havenv1.OIDCClientSpec{
			PlaneRef: havenv1.PlaneRef{Name: "platform", Namespace: "identity"}, ServiceAccount: true,
		},
	}
	e := newOCEnv(t, plane, job, spa(), webApp())
	e.r.Providers = ProviderFactoryFunc(func(context.Context, *havenv1.IdentityPlane) (idp.Provider, error) { return admin, nil })
	ctx := context.Background()

	for _, n := range []string{"job", "spa", "web"} {
		e.reconcile(n)
		e.wantCond(n, CondReady, "True", ReasonSynced)
	}
	find := func(clientID string) *idp.Client {
		c, err := admin.FindClientByClientID(ctx, "demo", clientID)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	if c := find("spa"); c == nil || !c.PublicClient || c.Attributes[pkceAttribute] != "S256" {
		t.Fatalf("spa client in the real IdP: %+v", c)
	}
	if c := find("web"); c == nil || c.PublicClient || !c.StandardFlowEnabled {
		t.Fatalf("web client in the real IdP: %+v", c)
	}

	tokenWith := func(id, secret string) int {
		req, _ := http.NewRequest(http.MethodPost, base+"/realms/demo/protocol/openid-connect/token",
			strings.NewReader(url.Values{"grant_type": {"client_credentials"}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(id, secret)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	secretOf := func(name string) string { return string(e.secret(name).Data["client-secret"]) }
	// The Secret holds the credential the real IdP actually accepts.
	if code := tokenWith("job", secretOf("job-oidc")); code != 200 {
		t.Fatalf("client_credentials with the Secret's value = %d, want 200", code)
	}

	// Idle reconcile: nothing is written to the real IdP or the cluster.
	e.writes, e.status = nil, 0
	e.reconcile("job")
	if len(e.writes) != 0 || e.status != 0 {
		t.Fatalf("idle reconcile wrote: %v status=%d", e.writes, e.status)
	}

	// Drift: the client vanishes in the IdP; the controller recreates it and
	// re-syncs the Secret with the new credential, and the old one is dead.
	old := secretOf("job-oidc")
	if err := admin.DeleteClient(ctx, "demo", find("job").ID); err != nil {
		t.Fatal(err)
	}
	e.reconcile("job")
	if code := tokenWith("job", secretOf("job-oidc")); code != 200 || secretOf("job-oidc") == old {
		t.Fatalf("after drift: token status %d, secret changed=%v", code, secretOf("job-oidc") != old)
	}
	if code := tokenWith("job", old); code == 200 {
		t.Fatal("the old secret still works after the client was recreated")
	}

	// Rotation through the annotation.
	before := secretOf("job-oidc")
	e.update("job", func(oc *havenv1.OIDCClient) { oc.Annotations = map[string]string{AnnotationRotateSecret: "1"} })
	e.reconcile("job")
	if code := tokenWith("job", secretOf("job-oidc")); code != 200 || secretOf("job-oidc") == before {
		t.Fatalf("after rotation: status %d", code)
	}
	if code := tokenWith("job", before); code == 200 {
		t.Fatal("rotated-out secret still accepted")
	}

	// Deletion removes the client from the real IdP.
	if err := e.c.Delete(ctx, e.get("job")); err != nil {
		t.Fatal(err)
	}
	e.reconcile("job")
	if c := find("job"); c != nil {
		t.Fatalf("client still in the IdP after deleting the OIDCClient: %+v", c)
	}
}
