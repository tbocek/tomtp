package tomtp

const maxBits = 64

type BitSet uint64

func New(bitSet uint64) *BitSet {
	b := BitSet(bitSet)
	return &b
}

func (b *BitSet) Set(i int, v uint32) {
	mask := uint64(1) << i
	if v == 0 {
		*b &^= BitSet(mask) // Clear the bit
	} else {
		*b |= BitSet(mask) // Set the bit
	}
}

func (b *BitSet) BitSet() uint64 {
	return uint64(*b)
}

func (b *BitSet) Len() int {
	return maxBits
}

func (b *BitSet) Test(i int) bool {
	return *b&(1<<i) != 0
}

func (b *BitSet) TestInt(i int) uint32 {
	return uint32((*b & (1 << i)) >> i)
}
