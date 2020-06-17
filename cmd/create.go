package cmd

import (
	"../archive"
	"crypto/rsa"
	"crypto/x509"
	"io"
	"log"
	"os"

	"github.com/spf13/cobra"
)

// createCmd represents the create command
var createCmd = &cobra.Command{
	Use:   "create",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: doCreateCmd,
}

var createOptions archive.NewArchiveOptions

var createOptionsMore struct {
	auBytes   uint32
	file      string
	publicKey string
}

func init() {
	rootCmd.AddCommand(createCmd)

	flag := createCmd.Flags()

	flag.Uint32Var(&createOptionsMore.auBytes, "au", 0x10000,
		"Allocation unit in bytes")
	flagEnumVar(flag, &createOptions.EndingCipher, "ending-cipher",
		"rsa", "Ending cipher", map[string]uint32{
			"null": archive.EndingCipherNull,
			"rsa":  archive.EndingCipherRSA,
		})
	flagEnumVar(flag, &createOptions.EndPointerChecksum, "end-pointer-checksum",
		"sha256", "Type of end pointer checksum", map[string]uint32{
			"crc32":  archive.EndPointerChecksumCRC32,
			"sha256": archive.EndPointerChecksumSHA256,
		})
	flag.UintVar(&createOptions.EndPointersHead, "end-pointers-head", 1,
		"Number of end pointers before the image area")
	flag.UintVar(&createOptions.EndPointersTail, "end-pointers-tail", 1,
		"Number of end pointers after the image area")
	flagEnumVar(flag, &createOptions.FillMethod, "fill", "random",
		"Method to fill unused space", map[string]uint32{
			"random": archive.FillRandom,
			"seek":   archive.FillSeek,
			"zero":   archive.FillZero,
		})
	flagEnumVar(flag, &createOptions.ImgCipher, "image-cipher", "xts-aes",
		"Image cipher", map[string]uint32{
			"null":    archive.ImgCipherNull,
			"xts-aes": archive.ImgCipherXTSAES,
		})
	flag.StringVar(&createOptionsMore.publicKey, "public-key", "",
		"RSA public key file name")
	flag.StringVar(&createOptionsMore.file, "file", "", "File")
	flag.Int64Var(&createOptions.DiskSize, "size", -1,
		"Output size in bytes")
}

func doCreateCmd(cmd *cobra.Command, args []string) {
	if err := cobra.NoArgs(cmd, args); err != nil {
		log.Println(err)
		os.Exit(1)
	}

	createOptions.GlobalLogs = []archive.LogConf{{
		Size: 1,
	}}
	createOptions.ImgLogs = []archive.LogConf{{
		Size: 1,
	}}

	if !(createOptionsMore.auBytes >= archive.BlockSize &&
		((createOptionsMore.auBytes & (createOptionsMore.auBytes - 1)) == 0)) {
		log.Println("Allocation unit must be power of 2 blocks")
		os.Exit(1)
	}
	createOptions.AlignmentBlocks = int64(createOptionsMore.auBytes / archive.BlockSize)

	createOptions.ImgClusterSizeExp = bytesToBlkExp(createOptionsMore.auBytes)

	if createOptions.EndingCipher == archive.EndingCipherRSA {
		if len(createOptionsMore.publicKey) == 0 {
			log.Println("Public key not given")
			os.Exit(1)
		}
		createOptions.PublicKeyRSA = readPublicKeyFile(
			createOptionsMore.publicKey)
	} else if len(createOptionsMore.publicKey) != 0 {
		log.Println("Cipher is null, but public key is given")
		os.Exit(1)
	}

	archive.RandReaderInit()

	var file *os.File
	if len(createOptionsMore.file) == 0 {
		log.Println("File not given")
		os.Exit(1)
	} else if createOptionsMore.file == "-" {
		file = os.Stdout
	} else {
		var err error
		flag := os.O_WRONLY
		if createOptions.DiskSize > 0 {
			flag |= os.O_CREATE
		}
		file, err = os.OpenFile(createOptionsMore.file, flag, 0666)
		if err != nil {
			log.Println("Error opening output", err)
			os.Exit(1)
		}
	}
	createOptions.Output = file

	if createOptions.DiskSize <= 0 {
		size, err := file.Seek(0, io.SeekEnd)
		if err != nil {
			log.Println("Error querying output size", err)
			os.Exit(1)
		}
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			log.Println(err)
			os.Exit(1)
		}
		if size == 0 {
			log.Println("Output size is 0")
			os.Exit(1)
		}
		createOptions.DiskSize = size
	}

	err := archive.WriteEmptyArchive(&createOptions)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	if err := file.Sync(); err != nil {
		log.Println(err)
		os.Exit(1)
	}
}

func bytesToBlkExp(n uint32) uint8 {
	if n < archive.BlockSize || (n&(n-1)) != 0 {
		log.Printf("Not a power of 2 times block size %d\n", n)
		os.Exit(1)
	}
	n /= 2 * archive.BlockSize
	r := uint8(0)
	for n != 0 {
		r++
		n >>= 1
	}
	return r
}

func readPublicKeyFile(name string) *rsa.PublicKey {
	key, err := x509.ParsePKCS1PublicKey(readMaybePEM(name,
		"RSA PUBLIC KEY"))
	if err != nil {
		log.Println("Error parsing key file:", err)
		os.Exit(1)
	}

	return key
}
