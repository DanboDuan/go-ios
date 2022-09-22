package zipconduit

import (
	"archive/zip"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
)

//sadly apple does not use a standard compliant zip implementation for this
//so I had to hack my own basic pseudo zip format together.
//this is for a directory.
func newZipHeaderDir(name string) (ZipHeader, []byte, []byte) {
	return ZipHeader{
		Signature:              0x04034b50,
		Version:                20,
		GeneralPurposeBitFlags: 0,
		CompressionMethod:      0,
		LastModifiedTime:       0xBDEF,
		LastModifiedDate:       0x52EC,
		Crc32:                  0,
		CompressedSize:         0,
		UncompressedSize:       0,
		FileNameLength:         uint16(len(name)),
		ExtraFieldLength:       32,
	}, []byte(name), zipExtraBytes
}

//sadly apple does not use a standard compliant zip implementation for this
//so I had to hack my own basic pseudo zip format together.
//this is for a file. It returns the file header, the bytes for the file name and an extra.
func newZipHeader(size uint32, crc32 uint32, name string) (ZipHeader, []byte, []byte) {
	//the predefined values are just random ones I grabbed from a hexdump
	//since we only want to get files to a device so it can install an app
	//timestamps and all that don't really matter anyway
	return ZipHeader{
		Signature:              0x04034b50,
		Version:                20,
		GeneralPurposeBitFlags: 0,
		CompressionMethod:      0,
		LastModifiedTime:       0xBDEF,
		LastModifiedDate:       0x52EC,
		Crc32:                  crc32,
		CompressedSize:         size,
		UncompressedSize:       size,
		FileNameLength:         uint16(len(name)),
		ExtraFieldLength:       32,
	}, []byte(name), zipExtraBytes

}

//will be set by init()
var zipExtraBytes []byte

func init() {
	/**
	Zip files can carry extra data in their file header fields.
	Those are usually things like timestamps or some unix permissions we don't really care about.
	Mostly XCode sends UT extras
	(https://commons.apache.org/proper/commons-compress/apidocs/org/apache/commons/compress/archivers/zip/X5455_ExtendedTimestamp.html)
	Since we only push data to the device and don't really care about correct timestamps or anything like that,
	I just dumped what XCode generates and always send the same extra.
	In this case I took a 0x5455 "UT" extra. Should it ever break, it'll be easy to fix.
	*/
	s := "55540D00 07F3A2EC 60F6A2EC 60F3A2EC 6075780B 000104F5 01000004 14000000"
	s = strings.ReplaceAll(s, " ", "")

	extra, err := hex.DecodeString(s)
	zipExtraBytes = extra
	if err != nil {
		log.Fatal("this is impossible to break", err)
	}
}

//zipHeader is pretty much the structure of a standard zip file header as can be found
//here f.ex. https://en.wikipedia.org/wiki/ZIP_(file_format)#Local_file_header
type ZipHeader struct {
	Signature              uint32
	Version                uint16
	GeneralPurposeBitFlags uint16
	CompressionMethod      uint16
	LastModifiedTime       uint16
	LastModifiedDate       uint16
	Crc32                  uint32
	CompressedSize         uint32
	UncompressedSize       uint32
	FileNameLength         uint16
	ExtraFieldLength       uint16
}

//standard header signature for central directory of a zip file
var centralDirectoryHeader []byte = []byte{0x50, 0x4b, 0x01, 0x02}

// Unzip is code I copied from https://golangcode.com/unzip-files-in-go/
// thank you guys for the cool helpful code examples :-D
func Unzip(src string, dest string) ([]string, uint64, error) {
	var overallSize uint64
	var filenames []string

	r, err := zip.OpenReader(src)
	if err != nil {
		return filenames, 0, err
	}
	defer r.Close()

	for _, f := range r.File {

		// Store filename/path for returning and using later on
		fpath := filepath.Join(dest, f.Name)

		// Check for ZipSlip. More Info: http://bit.ly/2MsjAWE
		if !strings.HasPrefix(fpath, filepath.Clean(dest)+string(os.PathSeparator)) {
			return filenames, 0, fmt.Errorf("%s: illegal file path", fpath)
		}

		filenames = append(filenames, fpath)

		if f.FileInfo().IsDir() {
			// Make Folder
			os.MkdirAll(fpath, os.ModePerm)
			continue
		}

		// Make File
		if err = os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
			return filenames, 0, err
		}

		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return filenames, 0, err
		}

		rc, err := f.Open()
		if err != nil {
			return filenames, 0, err
		}

		_, err = io.Copy(outFile, rc)
		//sizeStat, err := outFile.Stat()
		overallSize += f.UncompressedSize64
		// Close the file without defer to close before next iteration of loop
		outFile.Close()
		rc.Close()

		if err != nil {
			return filenames, 0, err
		}
	}
	return filenames, overallSize, nil
}
