// Package store is the append-only, crash-safe on-disk store of the
// receipts log.
//
// A data directory holds:
//
//	entries.dat         the entries, append-only (format below)
//	checkpoint.json     the latest signed tree head, replaced atomically
//	cosignatures.jsonl  witness cosignatures, one JSON object per line
//	LOCK                an advisory lock held while the store is open
//
// entries.dat starts with the 8-byte magic "RCPTLOG\x01". Each record is
//
//	uint32 length (big-endian) | 32-byte leaf hash | payload | uint32 CRC-32C
//
// where length is the payload length and the CRC covers every byte of
// the record before it. A record is written with one write(2) on a file
// opened O_APPEND, then fsync(2); only after both succeed does the
// caller sign a new tree head, write it to checkpoint.json (write to a
// temporary file, fsync, rename, fsync the directory) and acknowledge
// the entry. So every acknowledged entry is inside the checkpoint.
//
// Open reads every record, checks its CRC, hands it to a visitor (which
// rebuilds the tree and checks the leaf hash against the payload), and
// handles a damaged tail: damage within the last record-sized stretch of
// the file, past the checkpoint's tree size, is an interrupted append
// that was never acknowledged and is truncated; damage anywhere else is
// corruption and Open fails. Open never repairs data the checkpoint
// covers.
package store

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/christiaan839-beep/receipts-log/internal/merkle"
)

// File names inside the data directory.
const (
	EntriesFile      = "entries.dat"
	CheckpointFile   = "checkpoint.json"
	CosignaturesFile = "cosignatures.jsonl"
	LockFile         = "LOCK"
)

// Magic is the first 8 bytes of entries.dat.
const Magic = "RCPTLOG\x01"

const (
	headerSize  = 4 + merkle.HashSize
	trailerSize = 4
	// DefaultMaxPayload is the default largest entry payload.
	DefaultMaxPayload = 1 << 20
	// HardMaxPayload is the largest payload the format accepts.
	HardMaxPayload = 64 << 20
	maxCheckpoint  = 64 << 10
	maxCosigLine   = 64 << 10
)

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// Errors.
var (
	ErrCorrupt = errors.New("store: data is corrupt")
	ErrFailed  = errors.New("store: an earlier write failed; restart to recover")
	ErrRange   = errors.New("store: no such entry")
	ErrPayload = errors.New("store: payload size out of range")
)

// Visit is called by Open for each entry, in order. An error stops Open.
type Visit func(index uint64, leaf merkle.Hash, payload []byte) error

// Options configures Open.
type Options struct {
	// Dir is the data directory. It is created (mode 0700) if missing.
	Dir string
	// MaxPayload is the largest payload accepted; 0 means
	// DefaultMaxPayload. It must not be lowered below the largest
	// payload already stored.
	MaxPayload int
	// Logger receives recovery notices. Nil discards them.
	Logger *slog.Logger
}

// Store is an open data directory. Its methods are not safe for
// concurrent use with Append; the caller serialises writers and may run
// Read and Count concurrently with each other.
type Store struct {
	dir        string
	maxPayload int
	log        *slog.Logger
	lock       *os.File
	f          *os.File
	cosig      *os.File
	offsets    []int64
	end        int64
	failed     error
}

// Open opens or creates the store in opts.Dir.
//
// visitEntry is called for every stored entry and visitCosig for every
// stored cosignature line; either may be nil.
func Open(opts Options, visitEntry Visit, visitCosig func(line []byte) error) (*Store, error) {
	maxPayload := opts.MaxPayload
	if maxPayload == 0 {
		maxPayload = DefaultMaxPayload
	}
	if maxPayload < 1 || maxPayload > HardMaxPayload {
		return nil, fmt.Errorf("store: MaxPayload must be 1..%d", HardMaxPayload)
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if err := os.MkdirAll(opts.Dir, 0o700); err != nil {
		return nil, err
	}
	s := &Store{dir: opts.Dir, maxPayload: maxPayload, log: logger}
	ok := false
	defer func() {
		if !ok {
			s.Close()
		}
	}()

	lock, err := os.OpenFile(filepath.Join(opts.Dir, LockFile), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	s.lock = lock
	if err := lockFile(lock); err != nil {
		return nil, fmt.Errorf("store: %s is in use by another process: %w", opts.Dir, err)
	}

	ckSize, haveCheckpoint, err := s.checkpointSize()
	if err != nil {
		return nil, err
	}

	path := filepath.Join(opts.Dir, EntriesFile)
	_, statErr := os.Stat(path)
	created := errors.Is(statErr, os.ErrNotExist)
	if statErr != nil && !created {
		return nil, statErr
	}
	if created && haveCheckpoint {
		return nil, fmt.Errorf("%w: %s exists but %s is missing", ErrCorrupt, CheckpointFile, EntriesFile)
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	s.f = f
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	// A new file, or one left empty by a crash between its creation and
	// the first write, gets the magic.
	if created || (st.Size() == 0 && !haveCheckpoint) {
		if _, err := f.Write([]byte(Magic)); err != nil {
			return nil, err
		}
		if err := f.Sync(); err != nil {
			return nil, err
		}
		if err := syncDir(opts.Dir); err != nil {
			return nil, err
		}
		if st, err = f.Stat(); err != nil {
			return nil, err
		}
	}

	res, err := Scan(f, st.Size(), maxPayload, ckSize, visitEntry)
	if err != nil {
		return nil, err
	}
	if res.TornAt >= 0 {
		logger.Warn("truncating an interrupted append at the end of the entries file",
			"offset", res.TornAt, "bytes", st.Size()-res.TornAt, "entries", len(res.Offsets))
		if err := f.Truncate(res.TornAt); err != nil {
			return nil, err
		}
		if err := f.Sync(); err != nil {
			return nil, err
		}
	}
	if uint64(len(res.Offsets)) < ckSize {
		return nil, fmt.Errorf("%w: %s holds %d entries but the checkpoint covers %d",
			ErrCorrupt, EntriesFile, len(res.Offsets), ckSize)
	}
	s.offsets = res.Offsets
	s.end = res.End

	cosigPath := filepath.Join(opts.Dir, CosignaturesFile)
	cf, err := os.OpenFile(cosigPath, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	s.cosig = cf
	if err := s.loadCosignatures(visitCosig); err != nil {
		return nil, err
	}
	ok = true
	return s, nil
}

// ScanResult is the outcome of Scan.
type ScanResult struct {
	// Offsets holds the file offset of each valid record.
	Offsets []int64
	// End is the offset just past the last valid record.
	End int64
	// TornAt is the offset at which a damaged tail starts, or -1.
	TornAt int64
}

// Scan reads the entries in r (of the given size) and calls visit for
// each. minCount is the number of entries the checkpoint covers: damage
// before that entry, or damage longer than one maximum-size record, is
// corruption. Scan never panics on arbitrary input.
func Scan(r io.ReaderAt, size int64, maxPayload int, minCount uint64, visit Visit) (ScanResult, error) {
	res := ScanResult{TornAt: -1}
	if size < int64(len(Magic)) {
		return res, fmt.Errorf("%w: entries file is shorter than its header", ErrCorrupt)
	}
	var m [len(Magic)]byte
	if _, err := r.ReadAt(m[:], 0); err != nil {
		return res, err
	}
	if string(m[:]) != Magic {
		return res, fmt.Errorf("%w: entries file has the wrong magic", ErrCorrupt)
	}
	maxRecord := int64(headerSize + maxPayload + trailerSize)
	off := int64(len(Magic))
	br := bufio.NewReaderSize(io.NewSectionReader(r, off, size-off), 1<<20)
	var hdr [headerSize]byte
	payload := make([]byte, 0, 4096)
	for off < size {
		index := uint64(len(res.Offsets))
		damaged := func(why string) (ScanResult, error) {
			if index >= minCount && size-off <= maxRecord {
				res.TornAt = off
				res.End = off
				return res, nil
			}
			return res, fmt.Errorf("%w: entry %d at offset %d: %s", ErrCorrupt, index, off, why)
		}
		if size-off < headerSize+trailerSize {
			return damaged("truncated record")
		}
		if _, err := io.ReadFull(br, hdr[:]); err != nil {
			return res, err
		}
		n := int64(binary.BigEndian.Uint32(hdr[:4]))
		if n < 1 || n > int64(maxPayload) {
			return damaged(fmt.Sprintf("payload length %d out of range", n))
		}
		if size-off < headerSize+n+trailerSize {
			return damaged("truncated record")
		}
		if cap(payload) < int(n)+trailerSize {
			payload = make([]byte, n+trailerSize)
		}
		buf := payload[:n+trailerSize]
		if _, err := io.ReadFull(br, buf); err != nil {
			return res, err
		}
		crc := crc32.Update(crc32.Checksum(hdr[:], castagnoli), castagnoli, buf[:n])
		if crc != binary.BigEndian.Uint32(buf[n:]) {
			return damaged("checksum mismatch")
		}
		var leaf merkle.Hash
		copy(leaf[:], hdr[4:])
		if visit != nil {
			if err := visit(index, leaf, buf[:n:n]); err != nil {
				return res, fmt.Errorf("%w: entry %d: %v", ErrCorrupt, index, err)
			}
		}
		res.Offsets = append(res.Offsets, off)
		off += headerSize + n + trailerSize
		res.End = off
	}
	if res.End == 0 {
		res.End = off
	}
	return res, nil
}

// EncodeRecord returns the on-disk form of one entry.
func EncodeRecord(leaf merkle.Hash, payload []byte) []byte {
	buf := make([]byte, headerSize+len(payload)+trailerSize)
	binary.BigEndian.PutUint32(buf, uint32(len(payload)))
	copy(buf[4:], leaf[:])
	copy(buf[headerSize:], payload)
	crc := crc32.Checksum(buf[:headerSize+len(payload)], castagnoli)
	binary.BigEndian.PutUint32(buf[headerSize+len(payload):], crc)
	return buf
}

// Count returns the number of stored entries.
func (s *Store) Count() uint64 { return uint64(len(s.offsets)) }

// MaxPayload returns the largest accepted payload.
func (s *Store) MaxPayload() int { return s.maxPayload }

// Append writes one entry durably and returns its index. After any
// write or fsync error the store refuses further appends.
func (s *Store) Append(leaf merkle.Hash, payload []byte) (uint64, error) {
	if s.failed != nil {
		return 0, fmt.Errorf("%w: %v", ErrFailed, s.failed)
	}
	if len(payload) < 1 || len(payload) > s.maxPayload {
		return 0, ErrPayload
	}
	rec := EncodeRecord(leaf, payload)
	n, err := s.f.Write(rec)
	if err == nil && n != len(rec) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = s.f.Sync()
	}
	if err != nil {
		s.failed = err
		return 0, fmt.Errorf("%w: %v", ErrFailed, err)
	}
	s.offsets = append(s.offsets, s.end)
	s.end += int64(len(rec))
	return uint64(len(s.offsets) - 1), nil
}

// Read returns entry i, re-checking its checksum.
func (s *Store) Read(i uint64) (merkle.Hash, []byte, error) {
	if i >= uint64(len(s.offsets)) {
		return merkle.Hash{}, nil, ErrRange
	}
	off := s.offsets[i]
	var hdr [headerSize]byte
	if _, err := s.f.ReadAt(hdr[:], off); err != nil {
		return merkle.Hash{}, nil, err
	}
	n := int(binary.BigEndian.Uint32(hdr[:4]))
	if n < 1 || n > HardMaxPayload {
		return merkle.Hash{}, nil, fmt.Errorf("%w: entry %d length", ErrCorrupt, i)
	}
	buf := make([]byte, n+trailerSize)
	if _, err := s.f.ReadAt(buf, off+headerSize); err != nil {
		return merkle.Hash{}, nil, err
	}
	crc := crc32.Update(crc32.Checksum(hdr[:], castagnoli), castagnoli, buf[:n])
	if crc != binary.BigEndian.Uint32(buf[n:]) {
		return merkle.Hash{}, nil, fmt.Errorf("%w: entry %d checksum", ErrCorrupt, i)
	}
	var leaf merkle.Hash
	copy(leaf[:], hdr[4:])
	return leaf, buf[:n:n], nil
}

// checkpointSize returns the tree size recorded in checkpoint.json.
func (s *Store) checkpointSize() (uint64, bool, error) {
	data, err := s.ReadCheckpoint()
	if err != nil || data == nil {
		return 0, false, err
	}
	var ck struct {
		TreeSize *uint64 `json:"treeSize"`
	}
	if err := json.Unmarshal(data, &ck); err != nil || ck.TreeSize == nil {
		return 0, false, fmt.Errorf("%w: %s is not a tree head", ErrCorrupt, CheckpointFile)
	}
	return *ck.TreeSize, true, nil
}

// ReadCheckpoint returns the contents of checkpoint.json, or nil if it
// does not exist.
func (s *Store) ReadCheckpoint() ([]byte, error) {
	f, err := os.Open(filepath.Join(s.dir, CheckpointFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxCheckpoint+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxCheckpoint {
		return nil, fmt.Errorf("%w: %s is too large", ErrCorrupt, CheckpointFile)
	}
	return data, nil
}

// WriteCheckpoint atomically replaces checkpoint.json with data.
func (s *Store) WriteCheckpoint(data []byte) error {
	if s.failed != nil {
		return fmt.Errorf("%w: %v", ErrFailed, s.failed)
	}
	if err := WriteFileAtomic(s.dir, CheckpointFile, data); err != nil {
		s.failed = err
		return fmt.Errorf("%w: %v", ErrFailed, err)
	}
	return nil
}

// AppendCosignature durably appends one JSON line (without its newline).
func (s *Store) AppendCosignature(line []byte) error {
	if s.failed != nil {
		return fmt.Errorf("%w: %v", ErrFailed, s.failed)
	}
	if len(line) == 0 || len(line) > maxCosigLine || bytes.IndexByte(line, '\n') >= 0 {
		return errors.New("store: invalid cosignature line")
	}
	buf := append(append(make([]byte, 0, len(line)+1), line...), '\n')
	n, err := s.cosig.Write(buf)
	if err == nil && n != len(buf) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = s.cosig.Sync()
	}
	if err != nil {
		s.failed = err
		return fmt.Errorf("%w: %v", ErrFailed, err)
	}
	return nil
}

func (s *Store) loadCosignatures(visit func([]byte) error) error {
	st, err := s.cosig.Stat()
	if err != nil {
		return err
	}
	data, err := io.ReadAll(io.NewSectionReader(s.cosig, 0, st.Size()))
	if err != nil {
		return err
	}
	good := 0
	for good < len(data) {
		nl := bytes.IndexByte(data[good:], '\n')
		if nl < 0 {
			break // torn last line
		}
		line := data[good : good+nl]
		if visit != nil {
			if err := visit(line); err != nil {
				return fmt.Errorf("%w: %s at offset %d: %v", ErrCorrupt, CosignaturesFile, good, err)
			}
		}
		good += nl + 1
	}
	if good < len(data) {
		s.log.Warn("truncating an interrupted cosignature write", "offset", good)
		if err := s.cosig.Truncate(int64(good)); err != nil {
			return err
		}
		return s.cosig.Sync()
	}
	return nil
}

// Close releases the store.
func (s *Store) Close() error {
	var first error
	for _, f := range []*os.File{s.cosig, s.f, s.lock} {
		if f != nil {
			if err := f.Close(); err != nil && first == nil {
				first = err
			}
		}
	}
	s.cosig, s.f, s.lock = nil, nil, nil
	return first
}

// WriteFileAtomic writes data to dir/name: a temporary file is written
// and fsynced, renamed over the target, and the directory is fsynced.
func WriteFileAtomic(dir, name string, data []byte) error {
	tmp := filepath.Join(dir, "."+name+".tmp")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		os.Remove(tmp)
		return err
	}
	return syncDir(dir)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
