package entries

import (
	"reflect"
)

type EntryTypeID [16]byte

type Entry interface{}

type EntryCommon struct {
	EntryTypeID
	Size uint32
}

var IdCvtmMagic EntryTypeID = EntryTypeID{'C', 'V', 'T', 'M', '-', 'M', 'A', 'G', 'I', 'C', 0, 0, 0, 0, 0, 0}

type CvtmMagic struct {
	Checksum     [32]byte
	HeaderLength uint32
}

var IdAllocateOnce EntryTypeID = EntryTypeID{'A', 'L', 'L', 'O', 'C', 'A', 'T', 'E', '-', 'O', 'N', 'C', 'E', 0, 0, 0}

type AllocateOnce struct {
	AllocationIncrement uint32
}

var IdEndPointerChec EntryTypeID = EntryTypeID{'E', 'N', 'D', '-', 'P', 'O', 'I', 'N', 'T', 'E', 'R', '-', 'C', 'H', 'E', 'C'}

type EndPointerChec struct {
	Algo uint32
}

var IdEndPointerLoca EntryTypeID = EntryTypeID{'E', 'N', 'D', '-', 'P', 'O', 'I', 'N', 'T', 'E', 'R', '-', 'L', 'O', 'C', 'A'}

type EndPointerLoca struct {
	Blk uint32
}

var IdEndingCipher EntryTypeID = EntryTypeID{'E', 'N', 'D', 'I', 'N', 'G', '-', 'C', 'I', 'P', 'H', 'E', 'R', 0, 0, 0}

type EndingCipher struct {
	Algo uint32
	Key  []byte
}

var IdEndingSize EntryTypeID = EntryTypeID{'E', 'N', 'D', 'I', 'N', 'G', '-', 'S', 'I', 'Z', 'E', 0, 0, 0, 0, 0}

type EndingSize struct {
	Size uint32
}

var IdGlobalLogLocat EntryTypeID = EntryTypeID{'G', 'L', 'O', 'B', 'A', 'L', '-', 'L', 'O', 'G', '-', 'L', 'O', 'C', 'A', 'T'}

type GlobalLogLocat struct {
	Start uint32
	Count uint32
}

var IdImageArea EntryTypeID = EntryTypeID{'I', 'M', 'A', 'G', 'E', '-', 'A', 'R', 'E', 'A', 0, 0, 0, 0, 0, 0}

type ImageArea struct {
	Start uint32
	End   uint32
}

var IdImageBasic EntryTypeID = EntryTypeID{'I', 'M', 'A', 'G', 'E', '-', 'B', 'A', 'S', 'I', 'C', 0, 0, 0, 0, 0}

type ImageBasic struct {
	ImgCipher         uint32
	ImgClusterSizeExp byte
}

var IdImageLog EntryTypeID = EntryTypeID{'I', 'M', 'A', 'G', 'E', '-', 'L', 'O', 'G', 0, 0, 0, 0, 0, 0, 0}

type ImageLog struct {
	BlkCount uint32
}

var IdSdCid EntryTypeID = EntryTypeID{'S', 'D', '-', 'C', 'I', 'D', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

type SdCid struct {
	SdCid [15]byte
}

var IdNoMoreImages EntryTypeID = EntryTypeID{'N', 'O', '-', 'M', 'O', 'R', 'E', '-', 'I', 'M', 'A', 'G', 'E', 'S', 0, 0}

type NoMoreImages struct {
}

var IdEnding EntryTypeID = EntryTypeID{'E', 'N', 'D', 'I', 'N', 'G', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

type Ending struct {
	Length           uint32
	Start            uint32
	Prev             uint32
	DataClusterCount uint32
	ClusterSizeExp   byte
	ClustersOffset   uint32
}

var IdImageKey EntryTypeID = EntryTypeID{'I', 'M', 'A', 'G', 'E', '-', 'K', 'E', 'Y', 0, 0, 0, 0, 0, 0, 0}

type ImageKey struct {
	Key []byte
}

var IdImageLogLocati EntryTypeID = EntryTypeID{'I', 'M', 'A', 'G', 'E', '-', 'L', 'O', 'G', '-', 'L', 'O', 'C', 'A', 'T', 'I'}

type ImageLogLocati struct {
	Offset uint32
	Size   uint32
}

var TypeToID map[reflect.Type]EntryTypeID = map[reflect.Type]EntryTypeID{
	reflect.TypeOf(CvtmMagic{}):      IdCvtmMagic,
	reflect.TypeOf(AllocateOnce{}):   IdAllocateOnce,
	reflect.TypeOf(EndPointerChec{}): IdEndPointerChec,
	reflect.TypeOf(EndPointerLoca{}): IdEndPointerLoca,
	reflect.TypeOf(EndingCipher{}):   IdEndingCipher,
	reflect.TypeOf(EndingSize{}):     IdEndingSize,
	reflect.TypeOf(GlobalLogLocat{}): IdGlobalLogLocat,
	reflect.TypeOf(ImageArea{}):      IdImageArea,
	reflect.TypeOf(ImageBasic{}):     IdImageBasic,
	reflect.TypeOf(ImageLog{}):       IdImageLog,
	reflect.TypeOf(SdCid{}):          IdSdCid,
	reflect.TypeOf(NoMoreImages{}):   IdNoMoreImages,
	reflect.TypeOf(Ending{}):         IdEnding,
	reflect.TypeOf(ImageKey{}):       IdImageKey,
	reflect.TypeOf(ImageLogLocati{}): IdImageLogLocati,
}

type ArchiveHeaderWrite struct {
	CvtmMagic      CvtmMagic
	EndPointerChec EndPointerChec
	EndPointerLoca []EndPointerLoca
	EndingCipher   EndingCipher
	EndingSize     EndingSize
	GlobalLogLocat []GlobalLogLocat
	ImageArea      ImageArea
	ImageBasic     ImageBasic
	ImageLog       []ImageLog
	Optional       []Entry
}

type ArchiveHeaderRead struct {
	AllocateOnce   AllocateOnce
	EndPointerChec EndPointerChec
	EndPointerLoca []EndPointerLoca
	EndingCipher   EndingCipher
	EndingSize     EndingSize
	GlobalLogLocat []GlobalLogLocat
	ImageArea      ImageArea
	ImageBasic     ImageBasic
	ImageLog       []ImageLog
	SdCid          SdCid
}

type EndingRead struct {
	NoMoreImages   NoMoreImages
	Ending         Ending
	ImageKey       ImageKey
	ImageLogLocati []ImageLogLocati
}
