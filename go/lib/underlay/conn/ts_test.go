package conn

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestIntToByteToInt(t *testing.T) {
	var offset int64 = 1000
	buff := make([]byte, 8)
	int64ToByteSlice(offset, buff)
	assert.Equalf(t, []byte{0, 0, 0, 0, 0, 0, 0x03, 0xE8}, buff, "Int64ToByte")
	res, ok := byteSliceToInt64(buff)
	assert.Equalf(t, true, ok, "Conversion success")
	assert.Equalf(t, offset, res, "Offset convert and back")
}
