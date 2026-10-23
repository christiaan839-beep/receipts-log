package store

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/christiaan839-beep/receipts-log/internal/merkle"
)

func payloadN(i int) []byte { return []byte(fmt.Sprintf(`{"canonical":"entry-%d"}`, i)) }

func leafOf(p []byte) merkle.Hash { return merkle.LeafHash(p) }

// checkLeaves is a visitor that requires leaf == LeafHash(payload).
func checkLeaves(seen *[]merkle.Hash) Visit {
	return func(i uint64, leaf merkle.Hash, payload []byte) error {
		if leaf != leafOf(payload) {
			return errors.New("leaf mismatch")
		}
		*seen = append(*seen, leaf)
		return nil
	}
}

func openT(t *testing.T, dir string, seen *[]merkle.Hash) *Store {
	t.Helper()
	s, err := Open(Options{Dir: dir}, checkLeaves(seen), nil)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func fill(t *testing.T, s *Store, from, to int) {
	t.Helper()
	for i := from; i < to; i++ {
		p := payloadN(i)
		idx, err := s.Append(leafOf(p), p)
		if err != nil || idx != uint64(i) {
			t.Fatalf("append %d: idx=%d err=%v", i, idx, err)
		}
	}
}

func writeCheckpoint(t *testing.T, s *Store, size int) {
	t.Helper()
	if err := s.WriteCheckpoint([]byte(fmt.Sprintf(`{"treeSize":%d}`, size))); err != nil {
		t.Fatal(err)
	}
}

func TestAppendReadReopen(t *testing.T) {
	dir := t.TempDir()
	var seen []merkle.Hash
	s := openT(t, dir, &seen)
	fill(t, s, 0, 50)
	writeCheckpoint(t, s, 50)
	for i := 0; i < 50; i++ {
		leaf, p, err := s.Read(uint64(i))
		if err != nil || !bytes.Equal(p, payloadN(i)) || leaf != leafOf(p) {
			t.Fatalf("read %d: %v", i, err)
		}
	}
	if _, _, err := s.Read(50); !errors.Is(err, ErrRange) {
		t.Fatalf("read past end: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	seen = nil
	s = openT(t, dir, &seen)
	defer s.Close()
	if s.Count() != 50 || len(seen) != 50 {
		t.Fatalf("reopened with %d entries", s.Count())
	}
	fill(t, s, 50, 60)
	if s.Count() != 60 {
		t.Fatal("append after reopen")
	}
}

func TestPayloadLimits(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(Options{Dir: dir, MaxPayload: 16}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Append(merkle.Hash{}, nil); !errors.Is(err, ErrPayload) {
		t.Fatal("empty payload accepted")
	}
	if _, err := s.Append(merkle.Hash{}, make([]byte, 17)); !errors.Is(err, ErrPayload) {
		t.Fatal("oversized payload accepted")
	}
	if _, err := Open(Options{Dir: t.TempDir(), MaxPayload: HardMaxPayload + 1}, nil, nil); err == nil {
		t.Fatal("MaxPayload above the hard limit accepted")
	}
}

func TestLockExcludesSecondOpen(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(Options{Dir: dir}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(Options{Dir: dir}, nil, nil); err == nil {
		t.Fatal("second Open of a locked directory succeeded")
	}
	s.Close()
	s2, err := Open(Options{Dir: dir}, nil, nil)
	if err != nil {
		t.Fatalf("Open after Close: %v", err)
	}
	s2.Close()
}

// An append interrupted at any byte of its record is truncated on the
// next Open when the checkpoint does not cover it.
func TestTornTailEveryOffset(t *testing.T) {
	base := t.TempDir()
	src := filepath.Join(base, "src")
	var seen []merkle.Hash
	s := openT(t, src, &seen)
	fill(t, s, 0, 5)
	writeCheckpoint(t, s, 5)
	fill(t, s, 5, 6) // not checkpointed: never acknowledged
	s.Close()
	full, err := os.ReadFile(filepath.Join(src, EntriesFile))
	if err != nil {
		t.Fatal(err)
	}
	ck, _ := os.ReadFile(filepath.Join(src, CheckpointFile))
	lastLen := len(EncodeRecord(merkle.Hash{}, payloadN(5)))
	start := len(full) - lastLen
	for cut := start; cut < len(full); cut++ {
		dir := filepath.Join(base, fmt.Sprintf("cut%d", cut))
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(dir, EntriesFile), full[:cut], 0o600)
		os.WriteFile(filepath.Join(dir, CheckpointFile), ck, 0o600)
		seen = nil
		s, err := Open(Options{Dir: dir}, checkLeaves(&seen), nil)
		if err != nil {
			t.Fatalf("cut at %d: %v", cut, err)
		}
		if s.Count() != 5 {
			t.Fatalf("cut at %d: %d entries", cut, s.Count())
		}
		fill(t, s, 5, 7) // the log keeps working
		s.Close()
	}
	// A zeroed (unwritten) tail is also an interrupted append.
	dir := filepath.Join(base, "zeros")
	os.MkdirAll(dir, 0o700)
	os.WriteFile(filepath.Join(dir, EntriesFile), append(full[:start:start], make([]byte, lastLen)...), 0o600)
	os.WriteFile(filepath.Join(dir, CheckpointFile), ck, 0o600)
	s, err = Open(Options{Dir: dir}, nil, nil)
	if err != nil || s.Count() != 5 {
		t.Fatalf("zeroed tail: %v", err)
	}
	s.Close()
}

// Damage to an entry the checkpoint covers is never repaired.
func TestDamageInsideCheckpointFails(t *testing.T) {
	dir := t.TempDir()
	var seen []merkle.Hash
	s := openT(t, dir, &seen)
	fill(t, s, 0, 6)
	writeCheckpoint(t, s, 6)
	s.Close()
	path := filepath.Join(dir, EntriesFile)
	full, _ := os.ReadFile(path)

	// Truncate inside the last, checkpointed record.
	os.WriteFile(path, full[:len(full)-3], 0o600)
	if _, err := Open(Options{Dir: dir}, nil, nil); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("truncated checkpointed entry: %v", err)
	}
	// Flip a byte in the middle of the file.
	bad := append([]byte(nil), full...)
	bad[len(Magic)+headerSize+2] ^= 0x40
	os.WriteFile(path, bad, 0o600)
	if _, err := Open(Options{Dir: dir}, nil, nil); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("flipped byte: %v", err)
	}
	// Remove a whole record at the end.
	recLen := len(EncodeRecord(merkle.Hash{}, payloadN(5)))
	os.WriteFile(path, full[:len(full)-recLen], 0o600)
	if _, err := Open(Options{Dir: dir}, nil, nil); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("dropped checkpointed entry: %v", err)
	}
	// Wrong magic.
	bad = append([]byte(nil), full...)
	bad[0] = 'X'
	os.WriteFile(path, bad, 0o600)
	if _, err := Open(Options{Dir: dir}, nil, nil); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("bad magic: %v", err)
	}
	// Entries file missing while a checkpoint exists.
	os.Remove(path)
	if _, err := Open(Options{Dir: dir}, nil, nil); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("missing entries: %v", err)
	}
}

// A record whose checksum is right but whose leaf does not match its
// payload is rejected by the visitor.
func TestVisitorRejectsLeafMismatch(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(Options{Dir: dir}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Append(merkle.Hash{1}, []byte("x")); err != nil {
		t.Fatal(err)
	}
	s.Close()
	var seen []merkle.Hash
	if _, err := Open(Options{Dir: dir}, checkLeaves(&seen), nil); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("leaf mismatch: %v", err)
	}
}

func TestEmptyFileFromCrashAtCreate(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, EntriesFile), nil, 0o600)
	s, err := Open(Options{Dir: dir}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	fill(t, s, 0, 2)
	s.Close()
}

func TestCosignatures(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(Options{Dir: dir}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := s.AppendCosignature([]byte(fmt.Sprintf(`{"n":%d}`, i))); err != nil {
			t.Fatal(err)
		}
	}
	if s.AppendCosignature([]byte("a\nb")) == nil {
		t.Fatal("line with newline accepted")
	}
	s.Close()
	// Simulate a torn final line.
	f, _ := os.OpenFile(filepath.Join(dir, CosignaturesFile), os.O_WRONLY|os.O_APPEND, 0o600)
	f.Write([]byte(`{"n":`))
	f.Close()
	var lines []string
	s, err = Open(Options{Dir: dir}, nil, func(l []byte) error { lines = append(lines, string(l)); return nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 3 {
		t.Fatalf("lines %v", lines)
	}
	if err := s.AppendCosignature([]byte(`{"n":3}`)); err != nil {
		t.Fatal(err)
	}
	s.Close()
	lines = nil
	s, err = Open(Options{Dir: dir}, nil, func(l []byte) error { lines = append(lines, string(l)); return nil })
	if err != nil || len(lines) != 4 || lines[3] != `{"n":3}` {
		t.Fatalf("after repair: %v %v", err, lines)
	}
	s.Close()
	// A visitor error is corruption.
	if _, err := Open(Options{Dir: dir}, nil, func([]byte) error { return errors.New("bad") }); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("visitor error: %v", err)
	}
}

func TestWriteFileAtomic(t *testing.T) {
	dir := t.TempDir()
	if err := WriteFileAtomic(dir, "x", []byte("1")); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(dir, "x", []byte("2")); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "x"))
	if string(b) != "2" {
		t.Fatal("not replaced")
	}
	if _, err := os.Stat(filepath.Join(dir, ".x.tmp")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("temporary file left behind")
	}
}

// FuzzScan runs the record scanner over arbitrary file contents. It must
// never panic, and every record it accepts must carry a valid checksum.
func FuzzScan(f *testing.F) {
	var file []byte
	file = append(file, Magic...)
	for i := 0; i < 3; i++ {
		file = append(file, EncodeRecord(leafOf(payloadN(i)), payloadN(i))...)
	}
	f.Add(file, uint64(0))
	f.Add(file[:len(file)-2], uint64(2))
	f.Add([]byte(Magic), uint64(0))
	f.Add([]byte{}, uint64(0))
	f.Fuzz(func(t *testing.T, data []byte, minCount uint64) {
		r := bytes.NewReader(data)
		res, err := Scan(r, int64(len(data)), 1<<12, minCount%8, func(i uint64, leaf merkle.Hash, p []byte) error {
			if len(p) == 0 {
				t.Fatal("empty payload visited")
			}
			return nil
		})
		if err != nil {
			return
		}
		if res.End > int64(len(data)) || (res.TornAt >= 0 && res.TornAt != res.End) {
			t.Fatalf("inconsistent result %+v for %d bytes", res, len(data))
		}
		for i, off := range res.Offsets {
			if off < int64(len(Magic)) || off >= res.End {
				t.Fatalf("offset %d out of range", i)
			}
		}
	})
}
