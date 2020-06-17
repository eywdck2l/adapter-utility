package archive

import (
	"./entries"
	"bufio"
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"reflect"
	"sort"
	"strings"
	"text/template"
)

const (
	maxHeaderSize = 0x100000
	maxEndingSize = 32
)

type ExtractOptions struct {
	File       *os.File
	PrivateKey *rsa.PrivateKey
	ImageNames *template.Template
	Overwrite  bool
	Raw        bool
}

// Read archive header

type badEntry struct {
	pos int
	err error
}

func (err badEntry) Error() string {
	return fmt.Sprintf("Bad entry at %d: %s", err.pos, err.err.Error())
}

type unknownEnum struct {
	name  string
	value uint32
}

func (e unknownEnum) Error() string {
	return fmt.Sprintf("Unknown enumeration value %s %d", e.name, e.value)
}

type errorList []error

func (e errorList) Error() string {
	st := make([]string, len(e))
	for i, v := range e {
		st[i] = v.Error()
	}
	return strings.Join(st, ", ")
}

type entryRead struct {
	at   int
	data []byte
}

func parseEntry(ent entryRead, dest reflect.Value) error {
	err := binary.Read(bytes.NewReader(ent.data), binary.LittleEndian, dest.Interface())
	if err == io.EOF {
		// Because the format allows fields to be added, an
		// entry missing some fields should not be an error.
		log.Println("Entry is shorter than expected at ", ent.at)
		return nil
	} else if err == io.ErrUnexpectedEOF {
		// But a field being incomplete shouldn't happen.
		return badEntry{ent.at, errors.New("Field is incomplete")}
	}

	// There is an error.  It's probably because binary doesn't read
	// into byte slices.  Handle them manually.

	r := bytes.NewReader(ent.data)
	err = forEachField(dest, func(v reflect.Value) error {
		if v.Kind() == reflect.Slice {
			// Only byte slices are supported.  And it is
			// expected to be the last field.
			at := ftell(r)
			if int(at) != len(ent.data) {
				v.Set(reflect.ValueOf(ent.data[at:]))
			}
			return nil
		}
		return binary.Read(r, binary.LittleEndian, v.Addr().Interface())
	})

	if err != nil {
		return badEntry{ent.at, err}
	}

	return nil
}

func splitEntries(data []byte, start int) (map[entries.EntryTypeID][]entryRead, error) {
	result := make(map[entries.EntryTypeID][]entryRead)

	for {
		if len(data) == 0 {
			break
		}
		if len(data) < 20 {
			return nil, badEntry{start, errors.New("entry crosses header boundary")}
		}
		entSize := int(binary.LittleEndian.Uint32(data[16:20]))
		if entSize > len(data) {
			return nil, badEntry{start, errors.New("entry crosses header boundary")}
		}
		var typeID entries.EntryTypeID
		copy(typeID[:], data[:16])
		result[typeID] = append(result[typeID], entryRead{start, data[20:entSize]})
		data = data[entSize:]
		start += entSize
	}

	return result, nil
}

func parseEntries(data []byte, bytesSkipped int, result interface{}) error {
	// Split data into entries

	ent, err := splitEntries(data, bytesSkipped)
	if err != nil {
		return err
	}

	// Parse entries

	err = forEachField(reflect.ValueOf(result).Elem(), func(v reflect.Value) error {
		var typeID entries.EntryTypeID

		switch v.Kind() {
		case reflect.Slice:
			// Multiple such entries are expected
			typ := v.Type()
			typeID = getTypeID(typ.Elem())
			toParse := ent[typeID]
			if len(toParse) == 0 {
				break
			}
			result := reflect.MakeSlice(typ, len(toParse), len(toParse))
			v.Set(result)
			for i, ent := range toParse {
				err := parseEntry(ent, result.Index(i))
				if err != nil {
					return err
				}
			}
		case reflect.Struct:
			// At most one such entry is expected
			typeID = getTypeID(v.Type())
			ent := ent[typeID]
			if len(ent) == 0 {
				// This entry is not given.  Keep
				// default value.
				break
			}
			if len(ent) > 1 {
				log.Printf("found more than 1 entries %#v\n", typeID)
			}
			err := parseEntry(ent[len(ent)-1], v)
			if err != nil {
				return err
			}
		default:
			gotBadType(v.Type())
		}

		delete(ent, typeID)

		return nil
	})

	if err != nil {
		return err
	}

	for name, ent := range ent {
		for _, ent := range ent {
			log.Printf("unknown entry at %d %#v\n", ent.at, name)
		}
	}

	return nil
}

func readArchiveHeader(options *ExtractOptions, result *entries.ArchiveHeaderRead) error {
	earlyEOF := errors.New("got EOF reading header")

	infile := bufio.NewReader(options.File)

	// Read first entry

	data := make([]byte, 56)
	if n, err := infile.Read(data); err != nil {
		return err
	} else if n != 56 {
		return earlyEOF
	}
	if !bytes.Equal(entries.IdCvtmMagic[:], data[:16]) {
		return errors.New("bad magic number")
	}
	firstEntSize := int(binary.LittleEndian.Uint32(data[16:20]))
	if firstEntSize < 56 {
		return fmt.Errorf("bad entry size %d", firstEntSize)
	}
	var firstEnt entries.CvtmMagic
	if err := binary.Read(bytes.NewReader(data[20:]), binary.LittleEndian, &firstEnt); err != nil {
		panic(err)
	}
	headerSize := firstEnt.HeaderLength
	if int(headerSize) < firstEntSize {
		return fmt.Errorf("bad header size %d", headerSize)
	} else if firstEnt.HeaderLength > maxHeaderSize {
		return fmt.Errorf("header size too big %d", headerSize)
	}

	// Read rest

	{
		data1 := make([]byte, headerSize)
		copy(data1, data)
		data = data1
	}
	if n, err := infile.Read(data[56:]); err != nil {
		return err
	} else if n != int(headerSize-56) {
		return earlyEOF
	}

	// Check checksum

	{
		checksum1 := make([]byte, 32)
		copy(checksum1, data[20:52])
		for i := 20; i < 52; i++ {
			data[i] = 0
		}
		checksum2 := sha256.Sum256(data)
		if !bytes.Equal(checksum1, checksum2[:]) {
			return errors.New("bad checksum")
		}
	}

	// Parse

	if err := parseEntries(data[firstEntSize:], firstEntSize, result); err != nil {
		return err
	}

	// Set default values

	if result.EndingSize.Size == 0 {
		result.EndingSize.Size = 1
	}

	if err := checkArchiveHeader(options, result, headerSize); err != nil {
		return err
	}

	return nil
}

func checkArchiveHeader(options *ExtractOptions, header *entries.ArchiveHeaderRead, headerSize uint32) error {
	// Only add to errs when the error certainly renders the archive
	// unreadable
	var errs errorList

	if header.EndingSize.Size > maxEndingSize {
		errs = append(errs, fmt.Errorf("end pointer too big %d blocks", header.EndingSize.Size))
	}

	switch header.EndingCipher.Algo {
	case EndingCipherNull:
		break
	case EndingCipherRSA:
		pub, err := x509.ParsePKCS1PublicKey(header.EndingCipher.Key)
		if err != nil {
			// Because the public key is not needed to read
			// the archive, only a warning is printed
			log.Println("Bad public key in archive", err)
			break
		}
		if options.PrivateKey == nil {
			errs = append(errs, errors.New("Archive is encrypted, but private key is not given"))
			break
		}
		pub1 := options.PrivateKey.Public().(*rsa.PublicKey)
		if !(pub.N.Cmp(pub1.N) == 0 && pub.E == pub1.E) {
			log.Println("Public key from archive header doesn't match private key")
		}
	default:
		errs = append(errs, unknownEnum{"EndingCipher.Algo", header.EndingCipher.Algo})
	}

	if header.EndPointerChec.Algo > 2 {
		errs = append(errs, unknownEnum{"EndPointerChec.Algo", header.EndPointerChec.Algo})
	}

	if len(header.EndPointerLoca) == 0 {
		errs = append(errs, errors.New("Archive has no end pointers"))
	}

	headerBlks := (headerSize + BlockSize - 1) / BlockSize

	if headerBlks > header.ImageArea.Start {
		log.Println("Header and image area overlap")
	}
	for _, e := range header.EndPointerLoca {
		if !((e.Blk >= headerBlks && e.Blk < header.ImageArea.Start) ||
			(e.Blk >= header.ImageArea.End)) {
			errs = append(errs, fmt.Errorf("Bad end pointer location %d", e.Blk))
		}
	}

	if len(errs) != 0 {
		return errs
	}
	return nil
}

// Find ending

func findEnd(infile *os.File, header *entries.ArchiveHeaderRead) (bytePos int64) {
	send := make(chan int64)

	for _, ent := range header.EndPointerLoca {
		go func(at int64) {
			buf := make([]byte, BlockSize)

			if _, err := infile.ReadAt(buf, at); err != nil {
				log.Println("Got error reading end pointer at", at, err)
				send <- 0
				return
			}

			chkSum := make([]byte, 32)
			copy(chkSum, buf[:32])
			if !bytes.Equal(chkSum, computeEndPointerChecksum(buf, header.EndPointerChec.Algo)) {
				log.Println("End pointer has bad checksum at", at)
				send <- 0
				return
			}

			send <- BlockSize * int64(binary.LittleEndian.Uint32(buf[32:36]))
		}(BlockSize * int64(ent.Blk))
	}

	for range header.EndPointerLoca {
		a := <-send
		if a > bytePos {
			bytePos = a
		}
	}

	return
}

// Extract image

var errNoMoreImages error = errors.New("No more images")

func readEnding(end int64, result *entries.EndingRead, options *ExtractOptions, header *entries.ArchiveHeaderRead) error {
	size := BlockSize * int64(header.EndingSize.Size)
	if end < size {
		return fmt.Errorf("Bad end pointer %d", end)
	}

	data := make([]byte, size)

	if _, err := options.File.ReadAt(data, end-size); err != nil {
		return err
	}

	switch header.EndingCipher.Algo {
	case EndingCipherNull:
		break
	case EndingCipherRSA:
		var err error
		data, err = rsa.DecryptOAEP(sha256.New(), nil, options.PrivateKey, data, []byte{})
		if err != nil {
			return err
		}
	default:
		panic(fmt.Sprintf("Unknown ending cipher %d", header.EndingCipher.Algo))
	}

	if bytes.Equal(entries.IdNoMoreImages[:], data[:16]) {
		return errNoMoreImages
	}

	if !bytes.Equal(entries.IdEnding[:], data[:16]) {
		return fmt.Errorf("Bad magic number for ending %#v", data[:16])
	}

	{
		size1 := binary.LittleEndian.Uint32(data[20:24])
		if int64(size1) > size {
			return fmt.Errorf("Bad ending size %d", size1)
		}
		data = data[:size1]
	}

	return parseEntries(data, 0, result)
}

func ftell(f io.Seeker) int64 {
	n, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		panic("can't seek" + err.Error())
	}
	return n
}

type infoExtractImage struct {
	Index int
}

type qcow3Header struct {
	Magic                 uint32
	Version               uint32
	BackingFileOffset     uint64
	BackingFileSize       uint32
	ClusterBits           uint32
	Size                  uint64
	CryptMethod           uint32
	L1Size                uint32
	L1TableOffset         uint64
	RefcountTableOffset   uint64
	RefcountTableClusters uint32
	NbSnapshots           uint32
	SnapshotsOffset       uint64
	IncompatibleFeatures  uint64
	CompatibleFeatures    uint64
	AutoclearFeatures     uint64
	RefcountOrder         uint32
	HeaderLength          uint32
}

func extractImage(options *ExtractOptions, index int, end int64, header *entries.ArchiveHeaderRead, ending *entries.EndingRead) error {
	start := BlockSize * int64(ending.Ending.Start)
	if start > end {
		return errors.New("Image start is after end")
	}
	allocatedBytes := end - start

	var dest *os.File
	{
		info := infoExtractImage{
			Index: index,
		}
		var name strings.Builder
		if err := options.ImageNames.Execute(&name, info); err != nil {
			return err
		}
		var err error
		flags := os.O_WRONLY | os.O_CREATE
		if options.Overwrite {
			flags |= os.O_TRUNC
		} else {
			flags |= os.O_EXCL
		}
		if dest, err = os.OpenFile(name.String(), flags, 0666); err != nil {
			return err
		}
	}
	defer dest.Close()

	src := options.File
	if _, err := src.Seek(start, io.SeekStart); err != nil {
		return err
	}

	if options.Raw {
		_, err := io.CopyN(dest, src, allocatedBytes)
		return err
	}

	dataClusterCount := ending.Ending.DataClusterCount
	clusterExp := 9 + ending.Ending.ClusterSizeExp
	allocatedClusters := (end - start + 512*int64(ending.Ending.ClustersOffset)) >> clusterExp
	l1Start := uint64(1) << clusterExp
	l1Data := make([]int32, -(int32(-dataClusterCount) >> (clusterExp - 2)))
	l1ClusterCount := -(-len(l1Data) >> (clusterExp - 4))
	regularClustersEntryOffset := 0x8000000000000000 | (l1Start + uint64(l1ClusterCount)<<clusterExp)

	loggedUnrecognized := false
	readIndex := func(r *accountingBufReader) (result int32, err error) {
		if err = binary.Read(r, binary.LittleEndian, &result); err != nil {
			return
		}
		if result < 0 {
			if result != -1 {
				if !loggedUnrecognized {
					loggedUnrecognized = true
					log.Printf("Got unrecognized cluster index %d in image %d at %d\n", result, index, r.pos)
				}
			}
		} else {
			if int64(result) > allocatedClusters {
				log.Printf("Got cluster number outside of image %d in image %d at %d\n", result, index, r.pos)
				result = -1
			}
		}
		return
	}

	{
		reader := newAccountingBufReader(src, 0)
		for i, _ := range l1Data {
			var err error
			l1Data[i], err = readIndex(reader)
			if err != nil {
				return err
			}
		}
	}

	// Data clusters are simply copied to output.  L2 tables need
	// some processing.  The locations of L2 tables are marked.

	var l2AtSrc []int
	for _, v := range l1Data {
		if v >= 0 {
			l2AtSrc = append(l2AtSrc, int(v))
		}
	}
	sort.Ints(l2AtSrc)
	countL2TablesBefore := func(srcCluster int32) int {
		return sort.SearchInts(l2AtSrc, int(srcCluster))
	}

	// Qcow2's L2 table entries are 8 bytes each.  Ours are 4 bytes
	// each.  Qcow2's L2 tables have half the number of entries.  So
	// 2 L2 tables are written for each L2 table read.

	// The generated image is not likely to be written to.  Thus to
	// save effort an empty reference count table is written, and
	// the dirty bit is set.

	// Write header

	if err := binary.Write(dest, binary.BigEndian, qcow3Header{
		Magic:                 0x514649fb,
		Version:               3,
		ClusterBits:           uint32(clusterExp),
		Size:                  uint64(dataClusterCount) << clusterExp,
		L1Size:                uint32(2 * len(l1Data)),
		L1TableOffset:         l1Start,
		RefcountTableOffset:   1 << clusterExp,
		RefcountTableClusters: 1,
		IncompatibleFeatures:  1, // Refcounts are inconsistent
		HeaderLength:          104,
	}); err != nil {
		return err
	}

	// Write L1 table

	writer := bufio.NewWriter(dest)
	defer writer.Flush()
	if _, err := dest.Seek(int64(l1Start), io.SeekStart); err != nil {
		return err
	}
	for _, l2 := range l1Data {
		entry := make([]byte, 16)
		if l2 < 0 {
			// Not allocated, write zeros
		} else {
			// Allocated
			// add the space used by doubling L2 tables
			at := regularClustersEntryOffset + ((uint64(countL2TablesBefore(l2)) + uint64(l2)) << clusterExp)
			binary.BigEndian.PutUint64(entry[0:8], at)
			binary.BigEndian.PutUint64(entry[8:16], at+(uint64(1)<<clusterExp))
		}
		if _, err := writer.Write(entry); err != nil {
			return err
		}
	}
	writer.Flush()

	// Write L2 table and data clusters

	if _, err := dest.Seek(int64(regularClustersEntryOffset&0x7fffffffffffffff), io.SeekStart); err != nil {
		return err
	}
	if _, err := src.Seek(start+512*int64(ending.Ending.ClustersOffset), io.SeekStart); err != nil {
		return err
	}
	lastL2 := 0
	for _, l2 := range l2AtSrc {
		if _, err := io.CopyN(dest, src, int64(l2-lastL2)<<clusterExp); err != nil {
			return err
		}
		lastL2 = l2

		reader := newAccountingBufReader(src, ftell(src)-start)
		for i := 0; i < 1<<(clusterExp-2); i++ {
			var entOut uint64
			var entIn int32
			entIn, err := readIndex(reader)
			if err != nil {
				return err
			}
			if entIn < 0 {
				entOut = 0
			} else {
				entOut = regularClustersEntryOffset + ((uint64(countL2TablesBefore(entIn)) + uint64(entIn)) << clusterExp)
			}
			if err := binary.Write(writer, binary.BigEndian, entOut); err != nil {
				return err
			}
		}
		writer.Flush()
	}
	if _, err := io.CopyN(dest, src, allocatedBytes-(int64(lastL2)<<clusterExp)); err != nil {
		return err
	}

	return nil
}

func ExtractArchive(options *ExtractOptions) error {
	var header entries.ArchiveHeaderRead
	if err := readArchiveHeader(options, &header); err != nil {
		return err
	}

	endAt := findEnd(options.File, &header)
	if endAt == 0 {
		return errors.New("No valid end pointer exists")
	}

	for index := 0; ; index++ {
		if endAt <= int64(header.ImageArea.Start) {
			return fmt.Errorf("Image ending is outside of image area at %d", endAt)
		} else if endAt == int64(header.ImageArea.Start) {
			break
		}

		var ending entries.EndingRead
		err := readEnding(endAt, &ending, options, &header)
		if err == errNoMoreImages {
			break
		}
		if err != nil {
			return err
		}

		err = extractImage(options, index, endAt-BlockSize*int64(header.EndingSize.Size), &header, &ending)
		if err != nil {
			return fmt.Errorf("Error extracting image at %d %v", endAt, err)
		}

		endAtNext := BlockSize * int64(ending.Ending.Prev)
		if endAtNext >= endAt {
			return fmt.Errorf("Ending does not point backwards %d at %d", endAtNext, endAt)
		}
		endAt = endAtNext
	}

	return nil
}
