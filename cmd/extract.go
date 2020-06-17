package cmd

import (
	"../archive"
	"crypto/rsa"
	"crypto/x509"
	"log"
	"os"
	"text/template"

	"github.com/spf13/cobra"
)

// extractCmd represents the extract command
var extractCmd = &cobra.Command{
	Use:   "extract",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: doExtractCmd,
}

var extractOptions archive.ExtractOptions

var extractOptionsMore struct {
	file       string
	privateKey string
	imageNames string
}

func init() {
	rootCmd.AddCommand(extractCmd)

	flag := extractCmd.Flags()

	flag.StringVar(&extractOptionsMore.file, "file", "", "File")
	flag.StringVar(&extractOptionsMore.privateKey, "private-key", "",
		"RSA private key file name")
	flag.BoolVar(&extractOptions.Overwrite, "overwrite", false,
		"Allow extracted files to overwrite existing files")
	flag.StringVar(&extractOptionsMore.imageNames, "image-name", "image-{{.Index}}",
		"Template for names of extracted images")
	flag.BoolVar(&extractOptions.Raw, "raw", false,
		"Don't convert to QCOW2")
}

func doExtractCmd(cmd *cobra.Command, args []string) {
	if err := cobra.NoArgs(cmd, args); err != nil {
		log.Println(err)
		os.Exit(1)
	}

	var err error
	extractOptions.ImageNames, err = template.New("imageNames").Parse(extractOptionsMore.imageNames)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	if len(extractOptionsMore.privateKey) != 0 {
		extractOptions.PrivateKey = readPrivateKeyFile(
			extractOptionsMore.privateKey)
		if err := extractOptions.PrivateKey.Validate(); err != nil {
			log.Println(err)
			os.Exit(1)
		}
	}

	if len(extractOptionsMore.file) == 0 {
		log.Println("File not given")
		os.Exit(1)
	} else {
		var err error
		extractOptions.File, err = os.Open(extractOptionsMore.file)
		if err != nil {
			log.Println("Error opening input", err)
			os.Exit(1)
		}
	}

	if err := archive.ExtractArchive(&extractOptions); err != nil {
		log.Println(err)
		os.Exit(1)
	}
}

func readPrivateKeyFile(name string) *rsa.PrivateKey {
	key, err := x509.ParsePKCS1PrivateKey(readMaybePEM(name,
		"RSA PRIVATE KEY"))
	if err != nil {
		log.Println("Error parsing key file:", err)
		os.Exit(1)
	}

	return key
}
