package archive

import (
	"./entries"
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"reflect"
)

const BlockSize = 512

const (
	ImgCipherNull   = 0
	ImgCipherXTSAES = 1
)

const (
	EndingCipherNull = 0
	EndingCipherRSA  = 1
)

const (
	EndPointerChecksumSHA256 = 0
	EndPointerChecksumCRC32  = 1
)

var crc32cTable *crc32.Table = crc32.MakeTable(crc32.Castagnoli)

func gotBadType(t reflect.Type) {
	panic(fmt.Sprintf("bad type %s.%s", t.PkgPath(), t.Name()))
}

func forEachField(v reflect.Value, cb func(reflect.Value) error) error {
	var limit int
	var getter func(reflect.Value, int) reflect.Value
	switch v.Kind() {
	case reflect.Array, reflect.Slice:
		limit = v.Len()
		getter = reflect.Value.Index
	case reflect.Struct:
		limit = v.NumField()
		getter = reflect.Value.Field
	case reflect.Ptr:
		return cb(v.Elem())
	default:
		gotBadType(v.Type())
	}

	for i := 0; i < limit; i++ {
		v := getter(v, i)
		if v.Kind() == reflect.Interface {
			v = v.Elem()
		}
		if err := cb(v); err != nil {
			return err
		}
	}

	return nil
}

func computeEndPointerChecksum(data []byte, algo uint32) []byte {
	copy(data[:32], []byte("END-POINTER\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"))
	switch algo {
	case EndPointerChecksumSHA256:
		checksum := sha256.Sum256(data)
		return checksum[:]
	case EndPointerChecksumCRC32:
		result := make([]byte, 32)
		binary.LittleEndian.PutUint32(result[:4],
			crc32.Checksum(data, crc32cTable))
		return result
	default:
		panic(fmt.Sprintf("unrecognized checksum type %d", algo))
	}
}

func getTypeID(typ reflect.Type) entries.EntryTypeID {
	typeID, ok := entries.TypeToID[typ]
	if !ok {
		gotBadType(typ)
	}
	return typeID
}

// Helper readers and writers

const (
	FillSeek = iota
	FillZero
	FillRandom
)

type bufWriteSeeker struct {
	*bufio.Writer
	base io.Seeker
}

func (w *bufWriteSeeker) Seek(offset int64, whence int) (int64, error) {
	if err := w.Flush(); err != nil {
		return 0, err
	}
	return w.base.Seek(offset, whence)
}

func newBufWriteSeeker(w io.WriteSeeker) *bufWriteSeeker {
	return &bufWriteSeeker{
		Writer: bufio.NewWriter(w),
		base:   w,
	}
}

type accountingBufReader struct {
	reader *bufio.Reader
	pos    int64
}

func (r *accountingBufReader) Read(p []byte) (n int, err error) {
	n, err = r.reader.Read(p)
	r.pos += int64(n)
	return
}

func newAccountingBufReader(r io.Reader, start int64) *accountingBufReader {
	return &accountingBufReader{
		reader: bufio.NewReader(r),
		pos:    start,
	}
}

type fillSeeker struct {
	target io.WriteSeeker
	pos    int64
	method int
}

func (w *fillSeeker) Write(p []byte) (int, error) {
	n, err := w.target.Write(p)
	w.pos += int64(n)
	return n, err
}

func (w *fillSeeker) Seek(offset int64, whence int) (int64, error) {
	// Skip if no seeking is actually needed.  So we don't get an
	// error if the underlying FD doesn't support seeking.

	if (whence == io.SeekStart && offset == w.pos) ||
		(whence == io.SeekCurrent && offset == 0) {
		return w.pos, nil
	}

	if w.method == FillSeek {
		pos, err := w.target.Seek(offset, whence)
		if err == nil {
			w.pos = pos
		}
		return pos, err
	}

	// Find how much needs to be written

	switch whence {
	case io.SeekStart:
		offset -= w.pos
	case io.SeekCurrent:
		break
	default:
		return 0, fmt.Errorf("Unsupported seek whence %d", whence)
	}
	if offset < 0 {
		return 0, fmt.Errorf("Can't fill backwards from %d by %d", w.pos, offset)
	}

	// Fill

	var n int64
	var err error
	switch w.method {
	case FillZero:
		n, err = writeZeros(w.target, offset)
	case FillRandom:
		n, err = writeRandom(w.target, offset)
	default:
		panic(fmt.Sprintf("unknown fill method %d", w.method))
	}

	w.pos += n

	return w.pos, err
}

type sizeWriter struct {
	cnt int
}

func (w *sizeWriter) Write(p []byte) (int, error) {
	n := len(p)
	w.cnt += n
	return n, nil
}
