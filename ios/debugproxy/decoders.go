package debugproxy

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"os"
	"time"

	"github.com/danielpaulus/go-ios/ios"

	dtx "github.com/danielpaulus/go-ios/ios/dtx_codec"
	"github.com/danielpaulus/go-ios/ios/zipconduit"
	log "github.com/sirupsen/logrus"
)

type decoder interface {
	decode([]byte)
	close()
}

type dtxDecoder struct {
	jsonFilePath string
	binFilePath  string
	buffer       bytes.Buffer
	isBroken     bool
	log          *log.Entry
}

type MessageWithMetaInfo struct {
	DtxMessage   interface{}
	MessageType  string
	TimeReceived time.Time
	OffsetInDump int64
	Length       int
}

func NewDtxDecoder(jsonFilePath string, binFilePath string, log *log.Entry) decoder {
	return &dtxDecoder{jsonFilePath: jsonFilePath, binFilePath: binFilePath, buffer: bytes.Buffer{}, isBroken: false, log: log}
}
func (f *dtxDecoder) close() {

}

func (f *dtxDecoder) decode(data []byte) {

	file, err := os.OpenFile(f.binFilePath+".raw",
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Println(err)
	}

	file.Write(data)
	file.Close()

	if f.isBroken {
		//when an error happens while decoding, this flag prevents from flooding the logs with errors
		//while still dumping binary to debug later
		return
	}
	f.buffer.Write(data)
	slice := f.buffer.Next(f.buffer.Len())
	written := 0
	for {
		msg, remainingbytes, err := dtx.DecodeNonBlocking(slice)
		if dtx.IsIncomplete(err) {
			f.buffer.Reset()
			f.buffer.Write(slice)
			break
		}
		if err != nil {
			f.log.Errorf("Failed decoding DTX:%s, continuing bindumping", err)
			f.log.Info(fmt.Sprintf("%x", slice))
			f.isBroken = true
		}
		slice = remainingbytes

		file, err := os.OpenFile(f.binFilePath,
			os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Println(err)
		}
		s, _ := file.Stat()
		offset := s.Size()
		file.Write(msg.RawBytes)
		file.Close()

		file, err = os.OpenFile(f.jsonFilePath,
			os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Println(err)
		}

		type Alias dtx.Message
		auxi := ""
		if msg.HasAuxiliary() {
			auxi = msg.Auxiliary.String()
		}
		aux := &struct {
			AuxiliaryContents string
			*Alias
		}{
			AuxiliaryContents: auxi,
			Alias:             (*Alias)(&msg),
		}
		aux.RawBytes = nil
		jsonMetaInfo := MessageWithMetaInfo{aux, "dtx", time.Now(), offset, len(msg.RawBytes)}

		mylog := f.log
		if strings.Contains(f.binFilePath, "from-device") {
			mylog = f.log.WithFields(log.Fields{"d": "in"})
		}
		if strings.Contains(f.binFilePath, "to-device") {
			mylog = f.log.WithFields(log.Fields{"d": "out"})
		}
		logDtxMessageNice(mylog, msg)
		jsonmsg, err := json.Marshal(jsonMetaInfo)
		file.Write(jsonmsg)
		io.WriteString(file, "\n")
		file.Close()

		written += len(msg.RawBytes)
	}
}

func logDtxMessageNice(log *log.Entry, msg dtx.Message) {
	if msg.PayloadHeader.MessageType == dtx.Methodinvocation {
		expectsReply := ""
		if msg.ExpectsReply {
			expectsReply = "e"
		}
		log.Infof("%d.%d%s c%d %s %s", msg.Identifier, msg.ConversationIndex, expectsReply, msg.ChannelCode, msg.Payload[0], msg.Auxiliary)
		return
	}
	if msg.PayloadHeader.MessageType == dtx.Ack {
		log.Infof("%d.%d c%d Ack", msg.Identifier, msg.ConversationIndex, msg.ChannelCode)
		return
	}
	if msg.PayloadHeader.MessageType == dtx.UnknownTypeOne {
		log.Infof("type1: %x", msg.Payload[0])
		return
	}
	if msg.PayloadHeader.MessageType == dtx.ResponseWithReturnValueInPayload {
		log.Infof("%d.%d c%d response: %s", msg.Identifier, msg.ConversationIndex, msg.ChannelCode, msg.Payload[0])
		return
	}
	if msg.PayloadHeader.MessageType == dtx.DtxTypeError {
		log.Infof("%d.%d c%d error: %s", msg.Identifier, msg.ConversationIndex, msg.ChannelCode, msg.Payload[0])
		return
	}
	log.Infof("%+v", msg)

}

type binaryOnlyDumper struct {
	path string
}

//NewNoOpDecoder does nothing
func NewBinDumpOnly(jsonFilePath string, dumpFilePath string, log *log.Entry) decoder {
	return binaryOnlyDumper{dumpFilePath}
}
func (f binaryOnlyDumper) close() {

}

func (n binaryOnlyDumper) decode(bytes []byte) {
	writeBytes(n.path, bytes)
}

func writeBytes(filePath string, data []byte) {
	file, err := os.OpenFile(filePath,
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(fmt.Sprintf("Could not write to file error: %v path:'%s'", err, filePath))
	}

	file.Write(data)
	file.Close()
}

type ByteAndHexDumper struct {
	FileWriter *os.File
	HexWriter  *os.File
}

func (n ByteAndHexDumper) decode(bytes []byte) {
	n.FileWriter.Write(bytes)
	n.HexWriter.Write([]byte(hex.Dump(bytes)))
}

func (n ByteAndHexDumper) close() {
	n.FileWriter.Close()
	n.HexWriter.Close()
}

func NewStreamingZipConduit(jsonFilePath string, dumpFilePath string, log *log.Entry) decoder {
	writer, _ := os.OpenFile(dumpFilePath,
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	hex := fmt.Sprintf("%s.hex.txt", filepath.Base(dumpFilePath))
	hexWriter, _ := os.OpenFile(filepath.Join(filepath.Dir(dumpFilePath), hex),
		os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)
	decoder := ByteAndHexDumper{writer, hexWriter}
	return decoder
}

type StreamingZipConduitReader struct {
	Reader     io.Reader
	FileWriter *os.File
}

func NewStreamingZipConduitFromFile(jsonFilePath string, raw string, allPlist bool) {
	reader, _ := os.OpenFile(raw,
		os.O_RDONLY, 0)
	file, _ := os.OpenFile(jsonFilePath,
		os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)
	decoder := StreamingZipConduitReader{reader, file}
	if allPlist {
		decoder.ReadAllPlist()
	} else {
		decoder.ReadDeltaFromFile()
	}
}

func JSONPretty(value any) []byte {
	if data, err := json.MarshalIndent(value, "", "    "); err == nil {
		return data
	}
	return []byte{}
}

func (n StreamingZipConduitReader) ReadPlist() error {
	plistCodec := ios.NewPlistCodec()
	msg, err := plistCodec.Decode(n.Reader)
	if err != nil {
		return err
	}
	plist, err := ios.ParsePlist(msg)
	if err != nil {
		return err
	}
	n.FileWriter.Write(JSONPretty(plist))
	n.FileWriter.Write([]byte("\n"))
	return nil
}

func (n StreamingZipConduitReader) ReadAllPlist() {
	for {
		plistCodec := ios.NewPlistCodec()
		msg, err := plistCodec.Decode(n.Reader)
		if err != nil {
			break
		}
		plist, err := ios.ParsePlist(msg)
		if err != nil {
			break
		}
		n.FileWriter.Write(JSONPretty(plist))
		n.FileWriter.Write([]byte("\n"))
	}
	n.FileWriter.Close()
}

func (n StreamingZipConduitReader) ReadDeltaFromFile() {
	if err := n.ReadPlist(); err != nil {
		return
	}
	var zipHeader zipconduit.ZipHeader
	var signature uint32 = 0x04034b50
	plistFiles := map[string]string{
		"META-INF/com.apple.ZipMetadata.plist": "",
	}
	NoExtraBytesFiles := map[string]bool{
		"META-INF/com.apple.ZipMetadata.plist": true,
	}
	GeneralPurposeBitFlagsMap := make(map[uint16]*[]string)
	ZipExtraBytesMap := make(map[string]*[]string)
	ZipExtraBytesAfterMap := make(map[string]*[]string)

	for {
		if err := binary.Read(n.Reader, binary.LittleEndian, &zipHeader); err != nil {
			fmt.Printf("%+v", err)
			break
		}
		if zipHeader.Signature != signature {
			fmt.Println("err header")
		}
		n.FileWriter.Write(JSONPretty(zipHeader))
		n.FileWriter.Write([]byte("\n"))
		name := make([]byte, zipHeader.FileNameLength)
		if _, err := io.ReadFull(n.Reader, name); err != nil {
			fmt.Printf("%+v\n", err)
			break
		}
		n.FileWriter.Write(name)
		n.FileWriter.Write([]byte("\n"))
		fileName := string(name)
		fmt.Println(fileName)
		if value, ok := GeneralPurposeBitFlagsMap[zipHeader.GeneralPurposeBitFlags]; ok {
			*value = append(*value, fileName)
		} else {
			value := make([]string, 0)
			value = append(value, fileName)
			GeneralPurposeBitFlagsMap[zipHeader.GeneralPurposeBitFlags] = &value
		}
		zipExtraBytes := make([]byte, zipHeader.ExtraFieldLength)
		if _, err := io.ReadFull(n.Reader, zipExtraBytes); err != nil {
			fmt.Printf("%+v\n", err)
			break
		}

		key := hex.EncodeToString(zipExtraBytes)
		n.FileWriter.Write([]byte("zipExtraBytes before data hex ->" + key))
		n.FileWriter.Write([]byte("\n"))
		if value, ok := ZipExtraBytesMap[key]; ok {
			*value = append(*value, fileName)
		} else {
			value := make([]string, 0)
			value = append(value, fileName)
			ZipExtraBytesMap[key] = &value
		}
		fmt.Println("zipExtraBytes before for file --> ", fileName, key)

		if zipHeader.CompressedSize > 0 {
			data := make([]byte, zipHeader.CompressedSize)
			if _, err := io.ReadFull(n.Reader, data); err != nil {
				fmt.Printf("%+v\n", err)
				break
			}
			if _, v := plistFiles[fileName]; v {
				if plist, err := ios.ParsePlist(data); err == nil {
					n.FileWriter.Write(JSONPretty(plist))
					n.FileWriter.Write([]byte("\n"))
				} else {
					fmt.Printf("%+v", err)
				}
			}
		}
		if !strings.HasSuffix(fileName, "/") {
			if _, ok := NoExtraBytesFiles[fileName]; !ok {
				data := make([]byte, 16)
				if _, err := io.ReadFull(n.Reader, data); err != nil {
					fmt.Printf("%+v\n", err)
					break
				}
				key := hex.EncodeToString(data)
				n.FileWriter.Write([]byte("zipExtraBytes after data hex ->" + key))
				n.FileWriter.Write([]byte("\n"))
				if value, ok := ZipExtraBytesAfterMap[key]; ok {
					*value = append(*value, fileName)
				} else {
					value := make([]string, 0)
					value = append(value, fileName)
					ZipExtraBytesAfterMap[key] = &value
				}
				fmt.Println("zipExtraBytes after data for file -->", fileName, key)
			}
		}
	}
	n.FileWriter.Write(JSONPretty(GeneralPurposeBitFlagsMap))
	n.FileWriter.Write([]byte("\n"))
	n.FileWriter.Write(JSONPretty(ZipExtraBytesMap))
	n.FileWriter.Write([]byte("\n"))
	n.FileWriter.Write(JSONPretty(ZipExtraBytesAfterMap))
	n.FileWriter.Write([]byte("\n"))
	n.FileWriter.Close()
}

func (n StreamingZipConduitReader) ReadFromFile() {
	if err := n.ReadPlist(); err != nil {
		return
	}
	var zipHeader zipconduit.ZipHeader
	var signature uint32 = 0x04034b50
	plistFiles := map[string]string{
		"META-INF/com.apple.ZipMetadata.plist": "",
	}
	NoExtraBytesFiles := map[string]bool{
		"META-INF/com.apple.ZipMetadata.plist": true,
	}
	GeneralPurposeBitFlagsMap := make(map[uint16]*[]string)
	ZipExtraBytesMap := make(map[string]*[]string)
	ZipExtraBytesAfterMap := make(map[string]*[]string)

	for {
		if err := binary.Read(n.Reader, binary.LittleEndian, &zipHeader); err != nil {
			fmt.Printf("%+v", err)
			break
		}
		if zipHeader.Signature != signature {
			fmt.Println("err header")
		}
		n.FileWriter.Write(JSONPretty(zipHeader))
		n.FileWriter.Write([]byte("\n"))
		name := make([]byte, zipHeader.FileNameLength)
		if _, err := io.ReadFull(n.Reader, name); err != nil {
			fmt.Printf("%+v\n", err)
			break
		}
		n.FileWriter.Write(name)
		n.FileWriter.Write([]byte("\n"))
		fileName := string(name)
		fmt.Println(fileName)
		if value, ok := GeneralPurposeBitFlagsMap[zipHeader.GeneralPurposeBitFlags]; ok {
			*value = append(*value, fileName)
		} else {
			value := make([]string, 0)
			value = append(value, fileName)
			GeneralPurposeBitFlagsMap[zipHeader.GeneralPurposeBitFlags] = &value
		}
		zipExtraBytes := make([]byte, zipHeader.ExtraFieldLength)
		if _, err := io.ReadFull(n.Reader, zipExtraBytes); err != nil {
			fmt.Printf("%+v\n", err)
			break
		} else {
			key := hex.EncodeToString(zipExtraBytes)
			if value, ok := ZipExtraBytesMap[key]; ok {
				*value = append(*value, fileName)
			} else {
				value := make([]string, 0)
				value = append(value, fileName)
				ZipExtraBytesMap[key] = &value
			}
			fmt.Println("zipExtraBytes before for file --> ", fileName, key)
		}
		if zipHeader.CompressedSize > 0 {
			data := make([]byte, zipHeader.CompressedSize)
			if _, err := io.ReadFull(n.Reader, data); err != nil {
				fmt.Printf("%+v\n", err)
				break
			}
			if _, v := plistFiles[fileName]; v {
				if plist, err := ios.ParsePlist(data); err == nil {
					fmt.Printf("plist --> %s\n", JSONPretty(plist))
				} else {
					fmt.Printf("%+v", err)
				}
			}
		}
		if !strings.HasSuffix(fileName, "/") {
			if _, ok := NoExtraBytesFiles[fileName]; !ok {
				data := make([]byte, 16)
				if _, err := io.ReadFull(n.Reader, data); err != nil {
					fmt.Printf("%+v\n", err)
					break
				}
				key := hex.EncodeToString(data)
				if value, ok := ZipExtraBytesAfterMap[key]; ok {
					*value = append(*value, fileName)
				} else {
					value := make([]string, 0)
					value = append(value, fileName)
					ZipExtraBytesAfterMap[key] = &value
				}
				fmt.Println("zipExtraBytes after data for file -->", fileName, key)
			}
		}
	}
	n.FileWriter.Write(JSONPretty(GeneralPurposeBitFlagsMap))
	n.FileWriter.Write([]byte("\n"))
	n.FileWriter.Write(JSONPretty(ZipExtraBytesMap))
	n.FileWriter.Write([]byte("\n"))
	n.FileWriter.Write(JSONPretty(ZipExtraBytesAfterMap))
	n.FileWriter.Write([]byte("\n"))
	n.FileWriter.Close()
}

type BinaryPlistDumper struct {
	jsonFilePath string
	Writer       *io.PipeWriter
	Reader       *io.PipeReader
	FileWriter   *os.File
}

//NewNoOpDecoder does nothing
func NewBinaryPlist(jsonFilePath string, dumpFilePath string, log *log.Entry) decoder {
	reader, writer := io.Pipe()
	log.Println("==========")
	log.Println(jsonFilePath)
	log.Println("==========")
	file, _ := os.OpenFile(jsonFilePath,
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	decoder := BinaryPlistDumper{jsonFilePath, writer, reader, file}
	go decoder.Read()
	return decoder
}

func (n BinaryPlistDumper) close() {
	n.FileWriter.Close()
}

func (n BinaryPlistDumper) Read() {
	for {
		plistCodec := ios.NewPlistCodec()
		msg, err := plistCodec.Decode(n.Reader)
		if err != nil {
			break
		}
		plist, err := ios.ParsePlist(msg)
		if err != nil {
			break
		}
		n.FileWriter.Write(JSONPretty(plist))
		n.FileWriter.Write([]byte("\n"))
	}
	n.FileWriter.Close()
}

func (n BinaryPlistDumper) decode(bytes []byte) {
	n.Writer.Write(bytes)
}
