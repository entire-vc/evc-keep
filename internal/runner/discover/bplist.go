package discover

import (
	"bytes"
	"encoding/binary"
	"sort"
	"unicode/utf16"
	"unicode/utf8"
)

// The bplist00 trailer and marker layout follow Apple's CoreFoundation
// CFBinaryPList.c. Only dictionaries and their string entries are read;
// object references never recursively invoke the parser.
type binaryPlist struct {
	data           []byte
	offsets        []uint64
	table, refSize uint64
	bounds         map[uint64]uint64
}
type plistPair struct{ key, value uint64 }

func binaryPlistEntries(data []byte) ([]entry, error) {
	if len(data) < 40 || !bytes.Equal(data[:8], []byte("bplist00")) {
		return nil, ErrParse
	}
	t := data[len(data)-32:]
	offSize, refSize := uint64(t[6]), uint64(t[7])
	num, top, table := binary.BigEndian.Uint64(t[8:16]), binary.BigEndian.Uint64(t[16:24]), binary.BigEndian.Uint64(t[24:32])
	if offSize == 0 || offSize > 8 || refSize == 0 || refSize > 8 || num == 0 || num > 4096 || top >= num || table < 8 || table > (uint64(len(data))-32) || num > ((uint64(len(data))-32)-table)/offSize || table+num*offSize != (uint64(len(data))-32) {
		return nil, ErrParse
	}
	p := binaryPlist{data: data, table: table, refSize: refSize, offsets: make([]uint64, num)}
	for i := uint64(0); i < num; i++ {
		p.offsets[i] = readUint(data[table+i*offSize : table+(i+1)*offSize])
		if p.offsets[i] < 8 || p.offsets[i] >= table {
			return nil, ErrParse
		}
	}
	ordered := append([]uint64(nil), p.offsets...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	p.bounds = make(map[uint64]uint64, len(ordered))
	for i, pos := range ordered {
		if i > 0 && pos == ordered[i-1] {
			return nil, ErrParse
		}
		end := table
		if i+1 < len(ordered) {
			end = ordered[i+1]
		}
		p.bounds[pos] = end
	}
	pairs, err := p.dict(top)
	if err != nil {
		return nil, ErrParse
	}
	var env uint64
	found := false
	for _, pair := range pairs {
		name, e := p.text(pair.key)
		if e != nil {
			return nil, ErrParse
		}
		match := bytes.Equal(name, []byte("EnvironmentVariables"))
		wipe(name)
		if match {
			if found {
				return nil, ErrParse
			}
			env = pair.value
			found = true
		}
	}
	if !found {
		return []entry{}, nil
	}
	pairs, err = p.dict(env)
	if err != nil {
		return nil, ErrParse
	}
	out := []entry{}
	budget := len(data) * 2
	for _, pair := range pairs {
		name, e := p.text(pair.key)
		if e != nil {
			return out, ErrParse
		}
		value, e := p.text(pair.value)
		if e != nil || !validName(string(name)) {
			wipe(name)
			wipe(value)
			return out, ErrParse
		}
		budget -= len(name) + len(value)
		if budget < 0 {
			wipe(name)
			wipe(value)
			return out, ErrParse
		}
		out = append(out, entry{name: name, value: value})
	}
	return out, nil
}

func readUint(b []byte) uint64 {
	var n uint64
	for _, v := range b {
		n = n<<8 | uint64(v)
	}
	return n
}

func (p binaryPlist) object(id uint64, kind byte) (uint64, uint64, error) {
	if id >= uint64(len(p.offsets)) {
		return 0, 0, ErrParse
	}
	pos := p.offsets[id]
	limit := p.bounds[pos]
	marker := p.data[pos]
	pos++
	if marker&0xf0 != kind {
		return 0, 0, ErrParse
	}
	count := uint64(marker & 0xf)
	if count == 15 {
		if pos >= limit || p.data[pos]&0xf0 != 0x10 || p.data[pos]&0xf > 3 {
			return 0, 0, ErrParse
		}
		size := uint64(1) << (p.data[pos] & 0xf)
		pos++
		if size > limit-pos {
			return 0, 0, ErrParse
		}
		count = readUint(p.data[pos : pos+size])
		pos += size
	}
	return pos, count, nil
}

func (p binaryPlist) dict(id uint64) ([]plistPair, error) {
	pos, count, err := p.object(id, 0xd0)
	if err != nil || count > 4096 || count > (p.bounds[p.offsets[id]]-pos)/(2*p.refSize) {
		return nil, ErrParse
	}
	out := make([]plistPair, count)
	for i := uint64(0); i < count; i++ {
		k := readUint(p.data[pos+i*p.refSize : pos+(i+1)*p.refSize])
		v := readUint(p.data[pos+(count+i)*p.refSize : pos+(count+i+1)*p.refSize])
		if k >= uint64(len(p.offsets)) || v >= uint64(len(p.offsets)) {
			return nil, ErrParse
		}
		out[i] = plistPair{k, v}
	}
	return out, nil
}

// text returns nil on every error after wiping any partially decoded text.
func (p binaryPlist) text(id uint64) ([]byte, error) {
	if id >= uint64(len(p.offsets)) {
		return nil, ErrParse
	}
	kind := p.data[p.offsets[id]] & 0xf0
	if kind != 0x50 && kind != 0x60 {
		return nil, ErrParse
	}
	pos, count, err := p.object(id, kind)
	if err != nil {
		return nil, ErrParse
	}
	width := uint64(1)
	if kind == 0x60 {
		width = 2
	}
	if count > (p.bounds[p.offsets[id]]-pos)/width {
		return nil, ErrParse
	}
	raw := p.data[pos : pos+count*width]
	if kind == 0x50 {
		for _, v := range raw {
			if v > 127 {
				return nil, ErrParse
			}
		}
		return bytes.Clone(raw), nil
	}
	out := []byte{}
	for i := 0; i < len(raw); i += 2 {
		r := rune(binary.BigEndian.Uint16(raw[i : i+2]))
		if utf16.IsSurrogate(r) {
			if r > 0xdbff || i+4 > len(raw) {
				wipe(out)
				return nil, ErrParse
			}
			i += 2
			low := rune(binary.BigEndian.Uint16(raw[i : i+2]))
			if low < 0xdc00 || low > 0xdfff {
				wipe(out)
				return nil, ErrParse
			}
			r = utf16.DecodeRune(r, low)
		}
		var encoded [utf8.UTFMax]byte
		n := utf8.EncodeRune(encoded[:], r)
		out = appendWiped(out, encoded[:n])
		wipe(encoded[:])
	}
	return out, nil
}
