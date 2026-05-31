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
	"io/fs"
	"testing"
)

// sampleInventoryLines is a small inventory with a repeated subject (node1
// appears twice; its later serial 0003 is the current one).
var sampleInventoryLines = []string{
	"0001 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /node1",
	"0002 2024-01-02T00:00:00UTC 2029-01-02T00:00:00UTC /node2",
	"0003 2024-01-03T00:00:00UTC 2029-01-03T00:00:00UTC /node1",
}

// newInventoryService returns a StorageService over a fresh SQLite backend with
// the inventory touched, integrity initialised, and sampleInventoryLines
// appended. The backend is returned so tests can tamper with rows directly.
func newInventoryService(t *testing.T) (*StorageService, *SQLBackend) {
	t.Helper()
	ctx := context.Background()
	b := newSQLiteBackend(t)
	svc := NewWithBackend(b, "")
	if err := svc.TouchInventory(ctx); err != nil {
		t.Fatalf("TouchInventory: %v", err)
	}
	if err := svc.InitHMAC(ctx); err != nil {
		t.Fatalf("InitHMAC: %v", err)
	}
	for _, line := range sampleInventoryLines {
		if err := svc.AppendInventory(ctx, line); err != nil {
			t.Fatalf("AppendInventory(%q): %v", line, err)
		}
	}
	return svc, b
}

func TestSQLiteInventoryLatestSerialForSubject(t *testing.T) {
	ctx := context.Background()
	svc, _ := newInventoryService(t)

	// node1 was issued twice; the most recent serial wins.
	if got, err := svc.LatestSerialForSubject(ctx, "node1"); err != nil || got != "0003" {
		t.Errorf("LatestSerialForSubject(node1) = %q, %v; want 0003, nil", got, err)
	}
	if got, err := svc.LatestSerialForSubject(ctx, "node2"); err != nil || got != "0002" {
		t.Errorf("LatestSerialForSubject(node2) = %q, %v; want 0002, nil", got, err)
	}

	// An unknown subject wraps fs.ErrNotExist.
	_, err := svc.LatestSerialForSubject(ctx, "ghost")
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("LatestSerialForSubject(ghost) err = %v; want fs.ErrNotExist", err)
	}
}

func TestSQLiteInventoryRenderByteIdentical(t *testing.T) {
	ctx := context.Background()
	svc, _ := newInventoryService(t)

	var want bytes.Buffer
	for _, line := range sampleInventoryLines {
		want.WriteString(line)
		want.WriteByte('\n')
	}

	got, err := svc.ReadInventory(ctx)
	if err != nil {
		t.Fatalf("ReadInventory: %v", err)
	}
	if !bytes.Equal(got, want.Bytes()) {
		t.Errorf("rendered inventory = %q, want %q", got, want.Bytes())
	}
}

// TestSQLiteInventoryChainTamperDetection asserts the hash chain detects every
// kind of out-of-band edit to the inventory table: modification, insertion, and
// deletion of a row. Each mutates rows directly via the backend's db handle,
// bypassing AppendEntry so the stored head is not advanced.
func TestSQLiteInventoryChainTamperDetection(t *testing.T) {
	ctx := context.Background()

	t.Run("modified row", func(t *testing.T) {
		svc, b := newInventoryService(t)
		if _, err := b.db.NewUpdate().
			Model((*sqlInventoryRow)(nil)).
			Set("serial = ?", "DEAD").
			Where("subject = ?", "node2").
			Exec(ctx); err != nil {
			t.Fatalf("tamper update: %v", err)
		}
		if _, err := svc.ReadInventory(ctx); !errors.Is(err, ErrInventoryTampered) {
			t.Errorf("ReadInventory err = %v; want ErrInventoryTampered", err)
		}
	})

	t.Run("inserted row", func(t *testing.T) {
		svc, b := newInventoryService(t)
		if _, err := b.db.NewInsert().
			Model(&sqlInventoryRow{
				Serial:    "9999",
				Subject:   "rogue",
				NotBefore: "2024-06-01T00:00:00UTC",
				NotAfter:  "2029-06-01T00:00:00UTC",
			}).
			Exec(ctx); err != nil {
			t.Fatalf("tamper insert: %v", err)
		}
		if _, err := svc.ReadInventory(ctx); !errors.Is(err, ErrInventoryTampered) {
			t.Errorf("ReadInventory err = %v; want ErrInventoryTampered", err)
		}
	})

	t.Run("deleted row", func(t *testing.T) {
		svc, b := newInventoryService(t)
		if _, err := b.db.NewDelete().
			Model((*sqlInventoryRow)(nil)).
			Where("subject = ?", "node2").
			Exec(ctx); err != nil {
			t.Fatalf("tamper delete: %v", err)
		}
		if _, err := svc.ReadInventory(ctx); !errors.Is(err, ErrInventoryTampered) {
			t.Errorf("ReadInventory err = %v; want ErrInventoryTampered", err)
		}
	})
}

// TestInventoryMigrationRoundTrip migrates an inventory filesystem → sqlite →
// filesystem and asserts entries survive byte-for-byte and integrity verifies
// at each hop, even though the filesystem backend hashes the whole blob while
// the SQL backend uses a hash chain.
func TestInventoryMigrationRoundTrip(t *testing.T) {
	ctx := context.Background()

	// Source filesystem CA with inventory + integrity.
	src := New(t.TempDir())
	if err := src.EnsureDirs(ctx); err != nil {
		t.Fatalf("EnsureDirs: %v", err)
	}
	if err := src.SaveCACert(ctx, []byte("ca-cert-pem")); err != nil {
		t.Fatalf("SaveCACert: %v", err)
	}
	if err := src.TouchInventory(ctx); err != nil {
		t.Fatalf("TouchInventory: %v", err)
	}
	if err := src.InitHMAC(ctx); err != nil {
		t.Fatalf("InitHMAC: %v", err)
	}
	for _, line := range sampleInventoryLines {
		if err := src.AppendInventory(ctx, line); err != nil {
			t.Fatalf("AppendInventory: %v", err)
		}
	}
	srcText, err := src.ReadInventory(ctx)
	if err != nil {
		t.Fatalf("ReadInventory(src): %v", err)
	}

	// Migrate filesystem → sqlite.
	sqlite := NewWithBackend(newSQLiteBackend(t), "")
	if _, err := MigrateService(ctx, src, sqlite, MigrateOptions{}); err != nil {
		t.Fatalf("MigrateService fs→sqlite: %v", err)
	}
	// Integrity must verify on the structured destination.
	if err := sqlite.InitHMAC(ctx); err != nil {
		t.Fatalf("sqlite integrity after migrate: %v", err)
	}
	if got, _ := sqlite.ReadInventory(ctx); !bytes.Equal(got, srcText) {
		t.Errorf("sqlite inventory = %q, want %q", got, srcText)
	}
	if s, err := sqlite.LatestSerialForSubject(ctx, "node1"); err != nil || s != "0003" {
		t.Errorf("sqlite LatestSerialForSubject(node1) = %q, %v; want 0003, nil", s, err)
	}

	// Migrate sqlite → a second filesystem CA.
	dst := New(t.TempDir())
	if _, err := MigrateService(ctx, sqlite, dst, MigrateOptions{}); err != nil {
		t.Fatalf("MigrateService sqlite→fs: %v", err)
	}
	if err := dst.InitHMAC(ctx); err != nil {
		t.Fatalf("fs integrity after round-trip: %v", err)
	}
	if got, _ := dst.ReadInventory(ctx); !bytes.Equal(got, srcText) {
		t.Errorf("round-tripped inventory = %q, want %q", got, srcText)
	}
}
