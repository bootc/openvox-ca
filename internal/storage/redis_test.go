// Copyright (C) 2026 Chris Boot
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// newMiniredis starts an in-process fake Redis and returns a go-redis client
// wired to it plus a teardown.
func newMiniredis(t *testing.T) (*miniredis.Miniredis, *redis.Client, func()) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run: %v", err)
	}
	cli := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	return mr, cli, func() {
		_ = cli.Close()
		mr.Close()
	}
}

func newRedisBackend(t *testing.T, cli redis.UniversalClient, prefix string) *RedisBackend {
	t.Helper()
	b := NewRedisBackendFromClient(cli, prefix, 5*time.Second, 5*time.Second)
	if err := b.EnsureReady(); err != nil {
		t.Fatalf("EnsureReady: %v", err)
	}
	return b
}

func TestRedisBackendPutGetDelete(t *testing.T) {
	_, cli, stop := newMiniredis(t)
	defer stop()
	b := newRedisBackend(t, cli, "test1")

	if _, err := b.Get(KeyCACert); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Get on missing key: err = %v, want fs.ErrNotExist", err)
	}
	ok, err := b.Exists(KeyCACert)
	if err != nil || ok {
		t.Fatalf("Exists on missing key: ok=%v err=%v", ok, err)
	}

	payload := []byte("-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----\n")
	if err := b.Put(KeyCACert, payload, BlobPublic); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := b.Get(KeyCACert)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("Get returned %q, want %q", got, payload)
	}
	ok, err = b.Exists(KeyCACert)
	if err != nil || !ok {
		t.Fatalf("Exists after Put: ok=%v err=%v", ok, err)
	}

	if err := b.Delete(KeyCACert); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := b.Delete(KeyCACert); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Delete on missing: err = %v, want fs.ErrNotExist", err)
	}
}

func TestRedisBackendModTime(t *testing.T) {
	_, cli, stop := newMiniredis(t)
	defer stop()
	b := newRedisBackend(t, cli, "test-modtime")

	if _, err := b.ModTime(KeyCRL); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("ModTime on missing: err = %v, want fs.ErrNotExist", err)
	}

	before := time.Now().Add(-time.Second)
	if err := b.Put(KeyCRL, []byte("crl-data"), BlobPublic); err != nil {
		t.Fatalf("Put: %v", err)
	}
	mt, err := b.ModTime(KeyCRL)
	if err != nil {
		t.Fatalf("ModTime: %v", err)
	}
	if mt.Before(before) || mt.After(time.Now().Add(time.Second)) {
		t.Errorf("ModTime = %v, expected near now", mt)
	}
}

func TestRedisBackendList(t *testing.T) {
	_, cli, stop := newMiniredis(t)
	defer stop()
	b := newRedisBackend(t, cli, "test-list")

	subjects := []string{"alpha.example.com", "beta.example.com", "gamma.example.com"}
	for _, s := range subjects {
		if err := b.Put(CSRKey(s), []byte("csr:"+s), BlobPublic); err != nil {
			t.Fatalf("Put csr %s: %v", s, err)
		}
	}
	if err := b.Put(CertKey("alpha.example.com"), []byte("cert"), BlobPublic); err != nil {
		t.Fatalf("Put cert: %v", err)
	}

	csrs, err := b.List(csrPrefix)
	if err != nil {
		t.Fatalf("List csr: %v", err)
	}
	sort.Strings(csrs)
	want := []string{
		CSRKey("alpha.example.com"),
		CSRKey("beta.example.com"),
		CSRKey("gamma.example.com"),
	}
	if fmt.Sprint(csrs) != fmt.Sprint(want) {
		t.Errorf("List csr = %v, want %v", csrs, want)
	}

	certs, err := b.List(certPrefix)
	if err != nil {
		t.Fatalf("List cert: %v", err)
	}
	if len(certs) != 1 || certs[0] != CertKey("alpha.example.com") {
		t.Errorf("List cert = %v, want [%s]", certs, CertKey("alpha.example.com"))
	}

	if _, err := b.List("bogus/"); err == nil {
		t.Errorf("List with unknown prefix should error")
	}
}

// TestRedisBackendAppendLineConcurrent hammers AppendLine from several
// goroutines across two backends (simulating two replicas on one Redis) and
// asserts no lines are lost — the Lua append script is atomic server-side.
func TestRedisBackendAppendLineConcurrent(t *testing.T) {
	_, cli, stop := newMiniredis(t)
	defer stop()
	a := newRedisBackend(t, cli, "test-append")
	b := newRedisBackend(t, cli, "test-append")

	const writers = 4
	const perWriter = 25
	var wg sync.WaitGroup
	wg.Add(writers)
	for w := 0; w < writers; w++ {
		backend := a
		if w%2 == 1 {
			backend = b
		}
		w := w
		go func() {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				line := fmt.Sprintf("w%d-i%d\n", w, i)
				if err := backend.AppendLine(KeyInventory, []byte(line), BlobPrivate); err != nil {
					t.Errorf("AppendLine: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()

	data, err := a.Get(KeyInventory)
	if err != nil {
		t.Fatalf("Get after appends: %v", err)
	}
	lines := bytes.Split(bytes.TrimRight(data, "\n"), []byte{'\n'})
	if len(lines) != writers*perWriter {
		t.Errorf("got %d lines, want %d (no lines were lost?)", len(lines), writers*perWriter)
	}
}

func TestRedisBackendEndToEndViaStorageService(t *testing.T) {
	_, cli, stop := newMiniredis(t)
	defer stop()
	backend := newRedisBackend(t, cli, "test-service")
	svc := NewWithBackend(backend, filepath.Join(t.TempDir(), "private"))

	if err := svc.EnsureDirs(); err != nil {
		t.Fatalf("EnsureDirs: %v", err)
	}
	if err := svc.SaveCACert([]byte("ca-cert-pem")); err != nil {
		t.Fatalf("SaveCACert: %v", err)
	}
	if ok, _ := svc.HasCACert(); !ok {
		t.Errorf("HasCACert = false after SaveCACert")
	}
	if err := svc.WriteSerial("0001"); err != nil {
		t.Fatalf("WriteSerial: %v", err)
	}
	got, err := svc.GetSerial()
	if err != nil {
		t.Fatalf("GetSerial: %v", err)
	}
	if string(got) != "0001" {
		t.Errorf("GetSerial = %q, want 0001", got)
	}
	if err := svc.InitHMAC(); err != nil {
		t.Fatalf("InitHMAC: %v", err)
	}
	if err := svc.AppendInventory("line 1"); err != nil {
		t.Fatalf("AppendInventory: %v", err)
	}
	if err := svc.AppendInventory("line 2"); err != nil {
		t.Fatalf("AppendInventory: %v", err)
	}
	inv, err := svc.ReadInventory()
	if err != nil {
		t.Fatalf("ReadInventory: %v", err)
	}
	if string(inv) != "line 1\nline 2\n" {
		t.Errorf("ReadInventory = %q, want 'line 1\\nline 2\\n'", inv)
	}
	if err := svc.SaveCSR("node1", []byte("csr-pem")); err != nil {
		t.Fatalf("SaveCSR: %v", err)
	}
	if err := svc.SaveCert("node1", []byte("cert-pem")); err != nil {
		t.Fatalf("SaveCert: %v", err)
	}
	csrs, err := svc.ListCSRs()
	if err != nil {
		t.Fatalf("ListCSRs: %v", err)
	}
	if len(csrs) != 1 || csrs[0] != "node1" {
		t.Errorf("ListCSRs = %v, want [node1]", csrs)
	}
	certs, err := svc.ListCerts()
	if err != nil {
		t.Fatalf("ListCerts: %v", err)
	}
	if len(certs) != 1 || certs[0] != "node1" {
		t.Errorf("ListCerts = %v, want [node1]", certs)
	}
}

// TestRedisBackendAcquireLockMutualExclusion asserts two replicas sharing a
// Redis cannot both hold the same lock at once.
func TestRedisBackendAcquireLockMutualExclusion(t *testing.T) {
	_, cli, stop := newMiniredis(t)
	defer stop()
	a := newRedisBackend(t, cli, "test-lock-mutex")
	b := newRedisBackend(t, cli, "test-lock-mutex")
	defer a.Close()
	defer b.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ulA, err := a.AcquireLock(ctx, "crl")
	if err != nil {
		t.Fatalf("A AcquireLock: %v", err)
	}

	type result struct {
		got time.Time
		err error
	}
	ch := make(chan result, 1)
	startB := time.Now()
	go func() {
		ul, err := b.AcquireLock(ctx, "crl")
		res := result{got: time.Now(), err: err}
		if err == nil {
			_ = ul.Unlock()
		}
		ch <- res
	}()

	// Give B time to attempt and block on the SET NX retry loop.
	time.Sleep(200 * time.Millisecond)
	if err := ulA.Unlock(); err != nil {
		t.Fatalf("A Unlock: %v", err)
	}

	select {
	case res := <-ch:
		if res.err != nil {
			t.Fatalf("B AcquireLock: %v", res.err)
		}
		waited := res.got.Sub(startB)
		if waited < 150*time.Millisecond {
			t.Errorf("B acquired after %v; expected to wait ~200ms while A held the lock", waited)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("B never acquired the lock")
	}
}

// TestRedisBackendAcquireLockDistinctNames asserts distinct lock names do
// not contend.
func TestRedisBackendAcquireLockDistinctNames(t *testing.T) {
	_, cli, stop := newMiniredis(t)
	defer stop()
	b := newRedisBackend(t, cli, "test-lock-distinct")
	defer b.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ul1, err := b.AcquireLock(ctx, "subject:alpha")
	if err != nil {
		t.Fatalf("AcquireLock alpha: %v", err)
	}
	ul2, err := b.AcquireLock(ctx, "subject:beta")
	if err != nil {
		t.Fatalf("AcquireLock beta: %v", err)
	}
	if err := ul1.Unlock(); err != nil {
		t.Errorf("Unlock alpha: %v", err)
	}
	if err := ul2.Unlock(); err != nil {
		t.Errorf("Unlock beta: %v", err)
	}
}

// TestRedisBackendAcquireLockSerialisesConcurrentCallers asserts that many
// callers across two backends enter the critical section one-at-a-time.
func TestRedisBackendAcquireLockSerialisesConcurrentCallers(t *testing.T) {
	_, cli, stop := newMiniredis(t)
	defer stop()
	a := newRedisBackend(t, cli, "test-lock-serial")
	b := newRedisBackend(t, cli, "test-lock-serial")
	defer a.Close()
	defer b.Close()

	const workers = 6
	var inCritical atomic.Int32
	var maxConcurrent atomic.Int32
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		backend := a
		if i%2 == 1 {
			backend = b
		}
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			ul, err := backend.AcquireLock(ctx, "crl")
			if err != nil {
				t.Errorf("AcquireLock: %v", err)
				return
			}
			cur := inCritical.Add(1)
			for {
				m := maxConcurrent.Load()
				if cur <= m || maxConcurrent.CompareAndSwap(m, cur) {
					break
				}
			}
			time.Sleep(20 * time.Millisecond)
			inCritical.Add(-1)
			if err := ul.Unlock(); err != nil {
				t.Errorf("Unlock: %v", err)
			}
		}()
	}
	wg.Wait()
	if maxConcurrent.Load() != 1 {
		t.Errorf("maxConcurrent = %d, want 1 (lock did not serialise writers)", maxConcurrent.Load())
	}
}

// TestRedisBackendWithLockCrossBackend asserts StorageService.WithLock
// coordinates across two StorageService instances sharing a Redis.
func TestRedisBackendWithLockCrossBackend(t *testing.T) {
	_, cli, stop := newMiniredis(t)
	defer stop()
	a := newRedisBackend(t, cli, "test-withlock")
	b := newRedisBackend(t, cli, "test-withlock")
	svcA := NewWithBackend(a, filepath.Join(t.TempDir(), "a"))
	svcB := NewWithBackend(b, filepath.Join(t.TempDir(), "b"))

	var counter atomic.Int32
	var maxSeen atomic.Int32
	var wg sync.WaitGroup
	wg.Add(4)
	for i := 0; i < 4; i++ {
		svc := svcA
		if i%2 == 1 {
			svc = svcB
		}
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			err := svc.WithLock(ctx, "crl", func() error {
				cur := counter.Add(1)
				for {
					m := maxSeen.Load()
					if cur <= m || maxSeen.CompareAndSwap(m, cur) {
						break
					}
				}
				time.Sleep(20 * time.Millisecond)
				counter.Add(-1)
				return nil
			})
			if err != nil {
				t.Errorf("WithLock: %v", err)
			}
		}()
	}
	wg.Wait()
	if maxSeen.Load() != 1 {
		t.Errorf("maxSeen = %d, want 1", maxSeen.Load())
	}
}

// TestRedisBackendUnlockIdempotentOnExpiry verifies that Unlock after lock
// TTL has elapsed does not error and does not interfere with a subsequent
// AcquireLock holder — i.e. the unlock script's token check protects us.
func TestRedisBackendUnlockIdempotentOnExpiry(t *testing.T) {
	mr, cli, stop := newMiniredis(t)
	defer stop()
	// Short TTL so we can simulate expiry via miniredis's time control.
	a := NewRedisBackendFromClient(cli, "test-expiry", 5*time.Second, 100*time.Millisecond)
	if err := a.EnsureReady(); err != nil {
		t.Fatalf("EnsureReady: %v", err)
	}
	defer a.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ul, err := a.AcquireLock(ctx, "crl")
	if err != nil {
		t.Fatalf("AcquireLock: %v", err)
	}

	// Fast-forward past the lock TTL in miniredis; the key is now gone.
	mr.FastForward(5 * time.Second)

	// A different holder can now acquire.
	b := NewRedisBackendFromClient(cli, "test-expiry", 5*time.Second, 100*time.Millisecond)
	ul2, err := b.AcquireLock(ctx, "crl")
	if err != nil {
		t.Fatalf("AcquireLock after expiry: %v", err)
	}

	// Unlocking the original holder must not delete B's new lock (token mismatch).
	if err := ul.Unlock(); err != nil {
		t.Errorf("stale Unlock returned %v; should no-op", err)
	}

	// B's unlock should still succeed.
	if err := ul2.Unlock(); err != nil {
		t.Errorf("B Unlock: %v", err)
	}
}
