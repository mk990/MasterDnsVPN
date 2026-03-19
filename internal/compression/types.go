// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package compression

import (
	"bytes"
	"compress/flate"
	"io"
	"sync"
)

const (
	TypeOff  = 0
	TypeZSTD = 1
	TypeLZ4  = 2
	TypeZLIB = 3

	DefaultMinSize = 100
)

const availableTypeMask uint8 = (1 << TypeOff) | (1 << TypeZLIB)

var (
	deflateBufferPool = sync.Pool{
		New: func() any {
			return bytes.NewBuffer(make([]byte, 0, 256))
		},
	}
	deflateReaderPool = sync.Pool{
		New: func() any {
			return flate.NewReader(bytes.NewReader(nil))
		},
	}
	deflateWriterPool = sync.Pool{
		New: func() any {
			writer, _ := flate.NewWriter(io.Discard, 1)
			return writer
		},
	}
)

func NormalizeType(value uint8) uint8 {
	if value <= TypeZLIB {
		return value
	}
	return TypeOff
}

func IsTypeAvailable(value uint8) bool {
	value = NormalizeType(value)
	return availableTypeMask&(1<<value) != 0
}

func NormalizeAvailableType(value uint8) uint8 {
	if value > TypeZLIB || availableTypeMask&(1<<value) == 0 {
		return TypeOff
	}
	return value
}

func PackPair(uploadType uint8, downloadType uint8) uint8 {
	return (NormalizeType(uploadType) << 4) | NormalizeType(downloadType)
}

func SplitPair(value uint8) (uint8, uint8) {
	return NormalizeType((value >> 4) & 0x0F), NormalizeType(value & 0x0F)
}

func TypeName(value uint8) string {
	switch NormalizeType(value) {
	case TypeZSTD:
		return "ZSTD"
	case TypeLZ4:
		return "LZ4"
	case TypeZLIB:
		return "ZLIB"
	default:
		return "OFF"
	}
}

func CompressPayload(data []byte, compType uint8, minSize int) ([]byte, uint8) {
	if len(data) == 0 {
		return data, TypeOff
	}

	compType = NormalizeAvailableType(compType)
	if compType == TypeOff {
		return data, TypeOff
	}
	if minSize <= 0 {
		minSize = DefaultMinSize
	}
	if len(data) <= minSize {
		return data, TypeOff
	}

	switch compType {
	case TypeZLIB:
		buffer := deflateBufferPool.Get().(*bytes.Buffer)
		buffer.Reset()

		writer := deflateWriterPool.Get().(*flate.Writer)
		writer.Reset(buffer)
		_, err := writer.Write(data)
		if err == nil {
			err = writer.Close()
		}
		deflateWriterPool.Put(writer)
		if err != nil {
			buffer.Reset()
			deflateBufferPool.Put(buffer)
			return data, TypeOff
		}

		if buffer.Len() >= len(data) {
			buffer.Reset()
			deflateBufferPool.Put(buffer)
			return data, TypeOff
		}

		out := make([]byte, buffer.Len())
		copy(out, buffer.Bytes())
		buffer.Reset()
		deflateBufferPool.Put(buffer)
		return out, TypeZLIB
	default:
		return data, TypeOff
	}
}

func TryDecompressPayload(data []byte, compType uint8) ([]byte, bool) {
	if len(data) == 0 {
		return data, true
	}

	compType = NormalizeAvailableType(compType)
	if compType == TypeOff {
		return data, true
	}

	switch compType {
	case TypeZLIB:
		reader := bytes.NewReader(data)
		stream := deflateReaderPool.Get().(io.ReadCloser)
		stream.(flate.Resetter).Reset(reader, nil)
		buffer := deflateBufferPool.Get().(*bytes.Buffer)
		buffer.Reset()

		_, err := buffer.ReadFrom(stream)
		closeErr := stream.Close()
		deflateReaderPool.Put(stream)
		if err != nil || closeErr != nil || reader.Len() != 0 {
			buffer.Reset()
			deflateBufferPool.Put(buffer)
			return nil, false
		}

		out := make([]byte, buffer.Len())
		copy(out, buffer.Bytes())
		buffer.Reset()
		deflateBufferPool.Put(buffer)
		return out, true
	default:
		return nil, false
	}
}
