package archive

import (
	"./entries"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"reflect"
	"runtime"
)

type LogConf struct {
	Size uint32
}

type NewArchiveOptions struct {
	Output             io.WriteSeeker
	DiskSize           int64 // in bytes
	GlobalLogs         []LogConf
	ImgLogs            []LogConf
	EndPointersHead    uint
	EndPointersTail    uint
	EndingCipher       uint32
	EndPointerChecksum uint32
	PublicKeyRSA       *rsa.PublicKey
	ImgCipher          uint32
	ImgClusterSizeExp  uint8
	AlignmentBlocks    int64
	FillMethod         uint32
}

func alignWriter(w io.WriteSeeker, alignment int64) error {
	cur, err := w.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}

	_, err = w.Seek((alignment-1)&-cur, io.SeekCurrent)
	return err
}

var randReader *io.PipeReader

func writeRandWorker(w *io.PipeWriter, start <-chan struct{}, done chan<- struct{}) {
	buf := make([]byte, 0x400000)

	keyIV := make([]byte, 32)
	if _, err := rand.Read(keyIV); err != nil {
		panic(err)
	}

	blockCipher, err := aes.NewCipher(keyIV[0:16])
	if err != nil {
		panic(err)
	}

	streamCipher := cipher.NewCTR(blockCipher, keyIV[16:32])

	for {
		streamCipher.XORKeyStream(buf, buf)
		<-start
		if _, err := w.Write(buf); err != nil {
			panic(err)
		}
		done <- struct{}{}
	}
}

func RandReaderInit() {
	var writer *io.PipeWriter
	randReader, writer = io.Pipe()

	chFirst := make(chan struct{}, 1)
	chi := chFirst
	// Start the workers
	for i := runtime.NumCPU(); i != 0; i-- {
		t := make(chan struct{}, 1)
		go writeRandWorker(writer, chi, t)
		chi = t
	}
	// Connect the ends
	go writeRandWorker(writer, chi, chFirst)

	// Start
	chFirst <- struct{}{}
}

func writeZeros(w io.Writer, size int64) (int64, error) {
	var zeros [BlockSize]byte
	var written int64

	if size < 0 {
		panic(fmt.Sprintf("can't write backwards size %d", size))
	}

	n, err := w.Write(zeros[:size&(BlockSize-1)])
	written += int64(n)
	if err != nil {
		return written, err
	}

	for i := size / BlockSize; i != 0; i-- {
		n, err := w.Write(zeros[:])
		written += int64(n)
		if err != nil {
			return written, err
		}
	}

	return written, nil
}

func writeRandom(w io.Writer, size int64) (int64, error) {
	if size < 0 {
		panic(fmt.Sprintf("can't write backwards size %d", size))
	}

	return io.CopyN(w, randReader, size)
}

func writeEntry(w io.Writer, ent reflect.Value) error {
	// Write without the additional ID and size fields

	var wbare io.Writer

	var bare func(reflect.Value) error
	bare = func(ent reflect.Value) error {
		// binary supports it directly
		if s := binary.Size(ent.Interface()); s > 0 {
			return binary.Write(wbare, binary.LittleEndian, ent.Interface())
		}

		// binary doesn't support it directly.  It probably has
		// slices.
		return forEachField(ent, bare)
	}

	// Get entry size

	var sizer sizeWriter
	wbare = &sizer
	if err := bare(ent); err != nil {
		panic(err)
	}

	// Write

	wbare = w

	if err := binary.Write(w, binary.LittleEndian, entries.EntryCommon{
		EntryTypeID: getTypeID(ent.Type()),
		Size:        20 + uint32(sizer.cnt),
	}); err != nil {
		return err
	}
	if err := bare(ent); err != nil {
		return err
	}

	return nil
}

func writeMultipleEntries(w io.Writer, data interface{}) error {
	return forEachField(reflect.ValueOf(data), func(e reflect.Value) error {
		switch e.Kind() {
		case reflect.Array, reflect.Slice:
			// slice of entries
			limit := e.Len()
			for i := 0; i < limit; i++ {
				if err := writeEntry(w, e.Index(i)); err != nil {
					return err
				}
			}
		case reflect.Struct:
			// single entry
			return writeEntry(w, e)
		default:
			gotBadType(e.Type())
		}

		return nil
	})
}

func sizeOfHeader(header interface{}) int {
	var sizer sizeWriter
	if err := writeMultipleEntries(&sizer, header); err != nil {
		panic(err)
	}
	return sizer.cnt
}

func writeRepeatedly(dest io.WriteSeeker, data []byte, repeat uint, alignment int64) error {
	for ; repeat != 0; repeat-- {
		if _, err := dest.Write(data); err != nil {
			return err
		}
		if err := alignWriter(dest, alignment); err != nil {
			return err
		}
	}
	return nil
}

func writeImageEnding(dest io.Writer, ent []entries.Entry, cipher uint32, key *rsa.PublicKey, blocks uint) error {
	var buf bytes.Buffer
	if err := writeMultipleEntries(&buf, ent); err != nil {
		return err
	}
	data := buf.Bytes()

	if cipher == EndingCipherRSA {
		var err error
		data, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, key, data, []byte{})
		if err != nil {
			return err
		}
	}

	size := blocks * BlockSize
	if uint(len(data)) > size {
		return fmt.Errorf("Image ending too long, %d, max %d", len(data), size)
	}
	padTail := size - uint(len(data))

	// Write.  Always pad with random data
	if _, err := dest.Write(data); err != nil {
		return err
	}
	if padTail != 0 {
		if _, err := writeRandom(dest, int64(padTail)); err != nil {
			return err
		}
	}

	return nil
}

func alignUp(n int64, alignment int64) int64 {
	return (n + (alignment - 1)) & -alignment
}

func alignDown(n int64, alignment int64) int64 {
	return n & -alignment
}

func makeEndPointer(pointTo uint32, checksumType uint32) []byte {
	data := make([]byte, 512)

	binary.LittleEndian.PutUint32(data[32:36],
		uint32(pointTo))
	copy(data[:32], computeEndPointerChecksum(data, checksumType))

	return data
}

func WriteEmptyArchive(conf *NewArchiveOptions) error {
	var dest *fillSeeker
	{
		fileBuf := newBufWriteSeeker(conf.Output)
		defer fileBuf.Flush()
		dest = &fillSeeker{
			target: fileBuf,
			method: int(conf.FillMethod),
		}
	}

	alignment := conf.AlignmentBlocks

	// Put the correct number of each type of entries at the start,
	// so the header's size comes out right.
	header := entries.ArchiveHeaderWrite{
		EndPointerChec: entries.EndPointerChec{
			Algo: conf.EndPointerChecksum,
		},
		EndPointerLoca: make([]entries.EndPointerLoca,
			conf.EndPointersHead+conf.EndPointersTail),
		EndingCipher: entries.EndingCipher{
			Algo: conf.EndingCipher,
		},
		GlobalLogLocat: make([]entries.GlobalLogLocat, len(conf.GlobalLogs)),
		ImageLog:       make([]entries.ImageLog, len(conf.ImgLogs)),
		ImageBasic: entries.ImageBasic{
			ImgCipher:         conf.ImgCipher,
			ImgClusterSizeExp: conf.ImgClusterSizeExp,
		},
	}

	// Public key
	var endingSize uint32
	switch conf.EndingCipher {
	case EndingCipherNull:
		endingSize = 1
	case EndingCipherRSA:
		endingSize = uint32(alignUp(int64(conf.PublicKeyRSA.Size()), BlockSize))
		header.EndingCipher.Key = x509.MarshalPKCS1PublicKey(conf.PublicKeyRSA)
	default:
		panic(fmt.Sprintf(
			"WriteEmptyArchive: undefined ending cipher %d",
			conf.EndingCipher))
	}
	header.EndingSize.Size = endingSize

	// Find header size
	headerSize := sizeOfHeader(header)
	header.CvtmMagic.HeaderLength = uint32(headerSize)
	// imgStart is the first block of the image area.
	imgAreaStart := alignUp(int64(headerSize), alignment*BlockSize) / BlockSize

	// Image log
	for i, v := range conf.ImgLogs {
		header.ImageLog[i] = entries.ImageLog{
			BlkCount: v.Size,
		}
	}

	// Global logs
	for i, v := range conf.GlobalLogs {
		header.GlobalLogLocat[i] = entries.GlobalLogLocat{
			Start: uint32(imgAreaStart),
			Count: v.Size,
		}
		imgAreaStart += alignUp(int64(v.Size), alignment)
	}

	// End pointers
	// Put end pointers in different allocation units to reduce risk
	// of corruption caused by power loss when updating an end
	// pointer.
	endPointerStart := imgAreaStart
	for i := uint(0); i < conf.EndPointersHead; i++ {
		header.EndPointerLoca[i] = entries.EndPointerLoca{
			Blk: uint32(imgAreaStart),
		}
		imgAreaStart += alignment
	}
	imgAreaEnd := alignDown(conf.DiskSize/BlockSize, alignment)
	imgAreaEnd -= alignment * int64(conf.EndPointersTail)
	for i := uint(0); i < conf.EndPointersTail; i++ {
		header.EndPointerLoca[conf.EndPointersHead+i] = entries.EndPointerLoca{
			Blk: uint32(imgAreaEnd) + uint32(i)*uint32(alignment),
		}
	}

	header.ImageArea = entries.ImageArea{
		Start: uint32(imgAreaStart),
		End:   uint32(imgAreaEnd),
	}

	// Check there is enough space left for images.
	sentinelEnd := imgAreaStart + int64(header.EndingSize.Size)
	if sentinelEnd > imgAreaEnd {
		return fmt.Errorf(
			"Not enough space for images, start %d, end %d",
			sentinelEnd, imgAreaEnd)
	}

	// Compute checksum
	{
		hash := sha256.New()
		if err := writeMultipleEntries(hash, header); err != nil {
			panic(err)
		}
		copy(header.CvtmMagic.Checksum[:], hash.Sum(nil))
	}

	// Write header
	if err := writeMultipleEntries(dest, header); err != nil {
		return err
	}

	// Write zeros until the first end pointer.  This includes the
	// global log and any padding preceding it.
	if _, err := writeZeros(dest, endPointerStart*BlockSize-dest.pos); err != nil {
		return err
	}

	// Write the end pointers at the start
	endPointer := makeEndPointer(uint32(sentinelEnd),
		conf.EndPointerChecksum)
	if err := writeRepeatedly(dest, endPointer, conf.EndPointersHead, alignment*BlockSize); err != nil {
		return err
	}

	if _, err := dest.Seek(imgAreaStart*BlockSize, io.SeekStart); err != nil {
		return err
	}

	// Write the sentinel marking end of list of images
	if err := writeImageEnding(dest, []entries.Entry{
		entries.NoMoreImages{},
	}, conf.EndingCipher, conf.PublicKeyRSA, uint(endingSize)); err != nil {
		return err
	}

	// Fill the image space
	if _, err := dest.Seek(imgAreaEnd*BlockSize, io.SeekStart); err != nil {
		return err
	}

	// Write end pointers at the end
	if err := writeRepeatedly(dest, endPointer, conf.EndPointersTail, alignment*BlockSize); err != nil {
		return err
	}

	// Fill the space
	if _, err := dest.Seek(conf.DiskSize, io.SeekStart); err != nil {
		return err
	}

	return nil
}
