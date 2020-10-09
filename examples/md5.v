// md5 hash function implemented in v
// implementation based on https://tools.ietf.org/html/rfc1321
// and the book Applied Cryptography
import time

const (
	block_size = 64
	first_pad_byte = byte(0x80)
	padding_bytes = []byte{len:120, init:0}
	init_a = u32(0x67452301)
	init_b = u32(0xEFCDAB89)
	init_c = u32(0x98BADCFE)
	init_d = u32(0x10325476)
)

union U64Value {
mut:
    xu64 u64 = u64(0)
    bytes [8]byte
}

union U32Value {
mut:
    xu32 u32 = u32(0)
    bytes [4]byte
}

struct ABCD {
	a u32
	b u32
	c u32
	d u32
}

union WordBlock {
mut:
	bytes [64]byte
	u32_arr [16]u32
}

union MessageDigest {
mut:
	bytes [16]byte
	abcd  ABCD
}

struct MD5 {
	text string
}

// return the hexadecimal representation of the digest
pub fn (md5 MD5) hexdigest() string {
	return md5.digest().hex()
}

// return the digest
pub fn (md5 MD5) digest() []byte {
	return md5.encode()
}

// We first define four auxiliary functions that each take as input
// three 32-bit words and produce as output one 32-bit word.
[inline]
fn ff(x u32, y u32, z u32) u32 { return (x & y) | ((~x) & z) }

[inline]
fn fg(x u32, y u32, z u32) u32 { return (x & z) | (y & (~z)) }

[inline]
fn fh(x u32, y u32, z u32) u32 { return x ^ y ^ z }

[inline]
fn fi(x u32, y u32, z u32) u32 { return y ^ (x | (~z)) }

[inline]
fn rotate_left(x u32, n u32) u32 { return (x << n) | (x >> (32-n)) }


// create the md5 digest
fn (md5 MD5) encode() []byte {

	// Pre-processing: create the byte stream first
	mut message_bytes := md5.text.bytes()
	original_length := message_bytes.len*8  // we need the BITS length!!

	// Step 1. Append Padding Bits, the 0x80 will be always appended!!
	message_bytes << first_pad_byte

	message_length := message_bytes.len
	mod_result := message_length % block_size
	pad_length := if mod_result < 56 { 56 - mod_result } else { 120 - mod_result }

	message_bytes << padding_bytes[..pad_length]


	// Step 2. Append original length - always
	mut mlv := U64Value{}
	mlv.xu64 = u64(original_length)
	for b in mlv.bytes { message_bytes << b }

	// Step 3. Initialize MD Buffer
	mut a := init_a
	mut b := init_b
	mut c := init_c
	mut d := init_d

	// Step 4. Process Message in 16-Word Blocks. Here a word is meant to be a u32
	mut block := WordBlock{}
	for i := 0; i <= message_bytes.len-block_size; i += block_size {
		unsafe {
			C.memcpy(block.bytes, message_bytes[i..i+block_size].data, block_size)
		}

	// save current state
		mut aa := a
		mut bb := b
		mut cc := c
		mut dd := d

	// Round 1.
        a =  b + rotate_left(a + ff(b, c, d) + block.u32_arr[0]  + u32(0xD76AA478),  7)
        d =  a + rotate_left(d + ff(a, b, c) + block.u32_arr[1]  + u32(0xE8C7B756), 12)
        c =  d + rotate_left(c + ff(d, a, b) + block.u32_arr[2]  + u32(0x242070DB), 17)
        b =  c + rotate_left(b + ff(c, d, a) + block.u32_arr[3]  + u32(0xC1BDCEEE), 22)
        a =  b + rotate_left(a + ff(b, c, d) + block.u32_arr[4]  + u32(0xF57C0FAF),  7)
        d =  a + rotate_left(d + ff(a, b, c) + block.u32_arr[5]  + u32(0x4787C62A), 12)
        c =  d + rotate_left(c + ff(d, a, b) + block.u32_arr[6]  + u32(0xA8304613), 17)
        b =  c + rotate_left(b + ff(c, d, a) + block.u32_arr[7]  + u32(0xFD469501), 22)
        a =  b + rotate_left(a + ff(b, c, d) + block.u32_arr[8]  + u32(0x698098D8),  7)
        d =  a + rotate_left(d + ff(a, b, c) + block.u32_arr[9]  + u32(0x8B44F7AF), 12)
        c =  d + rotate_left(c + ff(d, a, b) + block.u32_arr[10] + u32(0xFFFF5BB1), 17)
        b =  c + rotate_left(b + ff(c, d, a) + block.u32_arr[11] + u32(0x895CD7BE), 22)
        a =  b + rotate_left(a + ff(b, c, d) + block.u32_arr[12] + u32(0x6B901122),  7)
        d =  a + rotate_left(d + ff(a, b, c) + block.u32_arr[13] + u32(0xFD987193), 12)
        c =  d + rotate_left(c + ff(d, a, b) + block.u32_arr[14] + u32(0xA679438E), 17)
        b =  c + rotate_left(b + ff(c, d, a) + block.u32_arr[15] + u32(0x49B40821), 22)

	// Round 2.
        a = b + rotate_left(a + fg(b, c, d) + block.u32_arr[1]  + u32(0xF61E2562),  5)
        d = a + rotate_left(d + fg(a, b, c) + block.u32_arr[6]  + u32(0xC040B340),  9)
        c = d + rotate_left(c + fg(d, a, b) + block.u32_arr[11] + u32(0x265E5A51), 14)
        b = c + rotate_left(b + fg(c, d, a) + block.u32_arr[0]  + u32(0xE9B6C7AA), 20)
        a = b + rotate_left(a + fg(b, c, d) + block.u32_arr[5]  + u32(0xD62F105D),  5)
        d = a + rotate_left(d + fg(a, b, c) + block.u32_arr[10] + u32(0x02441453),  9)
        c = d + rotate_left(c + fg(d, a, b) + block.u32_arr[15] + u32(0xD8A1E681), 14)
        b = c + rotate_left(b + fg(c, d, a) + block.u32_arr[4]  + u32(0xE7D3FBC8), 20)
        a = b + rotate_left(a + fg(b, c, d) + block.u32_arr[9]  + u32(0x21E1CDE6),  5)
        d = a + rotate_left(d + fg(a, b, c) + block.u32_arr[14] + u32(0xC33707D6),  9)
        c = d + rotate_left(c + fg(d, a, b) + block.u32_arr[3]  + u32(0xF4D50D87), 14)
        b = c + rotate_left(b + fg(c, d, a) + block.u32_arr[8]  + u32(0x455A14ED), 20)
        a = b + rotate_left(a + fg(b, c, d) + block.u32_arr[13] + u32(0xA9E3E905),  5)
        d = a + rotate_left(d + fg(a, b, c) + block.u32_arr[2]  + u32(0xFCEFA3F8),  9)
        c = d + rotate_left(c + fg(d, a, b) + block.u32_arr[7]  + u32(0x676F02D9), 14)
        b = c + rotate_left(b + fg(c, d, a) + block.u32_arr[12] + u32(0x8D2A4C8A), 20)

	// Round 3.
        a = b + rotate_left(a + fh(b, c, d) + block.u32_arr[5]  + u32(0xFFFA3942),  4)
        d = a + rotate_left(d + fh(a, b, c) + block.u32_arr[8]  + u32(0x8771F681), 11)
        c = d + rotate_left(c + fh(d, a, b) + block.u32_arr[11] + u32(0x6D9D6122), 16)
        b = c + rotate_left(b + fh(c, d, a) + block.u32_arr[14] + u32(0xFDE5380C), 23)
        a = b + rotate_left(a + fh(b, c, d) + block.u32_arr[1]  + u32(0xA4BEEA44),  4)
        d = a + rotate_left(d + fh(a, b, c) + block.u32_arr[4]  + u32(0x4BDECFA9), 11)
        c = d + rotate_left(c + fh(d, a, b) + block.u32_arr[7]  + u32(0xF6BB4B60), 16)
        b = c + rotate_left(b + fh(c, d, a) + block.u32_arr[10] + u32(0xBEBFBC70), 23)
        a = b + rotate_left(a + fh(b, c, d) + block.u32_arr[13] + u32(0x289B7EC6),  4)
        d = a + rotate_left(d + fh(a, b, c) + block.u32_arr[0]  + u32(0xEAA127FA), 11)
        c = d + rotate_left(c + fh(d, a, b) + block.u32_arr[3]  + u32(0xD4EF3085), 16)
        b = c + rotate_left(b + fh(c, d, a) + block.u32_arr[6]  + u32(0x04881D05), 23)
        a = b + rotate_left(a + fh(b, c, d) + block.u32_arr[9]  + u32(0xD9D4D039),  4)
        d = a + rotate_left(d + fh(a, b, c) + block.u32_arr[12] + u32(0xE6DB99E5), 11)
        c = d + rotate_left(c + fh(d, a, b) + block.u32_arr[15] + u32(0x1FA27CF8), 16)
        b = c + rotate_left(b + fh(c, d, a) + block.u32_arr[2]  + u32(0xC4AC5665), 23)


	// Round 4.
        a = b + rotate_left(a + fi(b, c, d) + block.u32_arr[0]  + u32(0xF4292244),  6)
        d = a + rotate_left(d + fi(a, b, c) + block.u32_arr[7]  + u32(0x432AFF97), 10)
        c = d + rotate_left(c + fi(d, a, b) + block.u32_arr[14] + u32(0xAB9423A7), 15)
        b = c + rotate_left(b + fi(c, d, a) + block.u32_arr[5]  + u32(0xFC93A039), 21)
        a = b + rotate_left(a + fi(b, c, d) + block.u32_arr[12] + u32(0x655B59C3),  6)
        d = a + rotate_left(d + fi(a, b, c) + block.u32_arr[3]  + u32(0x8F0CCC92), 10)
        c = d + rotate_left(c + fi(d, a, b) + block.u32_arr[10] + u32(0xFFEFF47D), 15)
        b = c + rotate_left(b + fi(c, d, a) + block.u32_arr[1]  + u32(0x85845DD1), 21)
        a = b + rotate_left(a + fi(b, c, d) + block.u32_arr[8]  + u32(0x6FA87E4F),  6)
        d = a + rotate_left(d + fi(a, b, c) + block.u32_arr[15] + u32(0xFE2CE6E0), 10)
        c = d + rotate_left(c + fi(d, a, b) + block.u32_arr[6]  + u32(0xA3014314), 15)
        b = c + rotate_left(b + fi(c, d, a) + block.u32_arr[13] + u32(0x4E0811A1), 21)
        a = b + rotate_left(a + fi(b, c, d) + block.u32_arr[4]  + u32(0xF7537E82),  6)
        d = a + rotate_left(d + fi(a, b, c) + block.u32_arr[11] + u32(0xBD3AF235), 10)
        c = d + rotate_left(c + fi(d, a, b) + block.u32_arr[2]  + u32(0x2AD7D2BB), 15)
        b = c + rotate_left(b + fi(c, d, a) + block.u32_arr[9]  + u32(0xEB86D391), 21)

	// increment with previously saved state
		a += aa
		b += bb
		c += cc
		d += dd
	}

	// Step 5. Output
	mut m_digest := MessageDigest{}
	m_digest.abcd = ABCD{a, b, c, d }
	mut msg_digest := []byte{cap: 16}

	for b_yte in m_digest.bytes { msg_digest << b_yte }

	return msg_digest
}

fn main() {
    sw := time.new_stopwatch({})
	for _ in 0..100000 {
		assert MD5{''}.hexdigest() == 'd41d8cd98f00b204e9800998ecf8427e'
		assert MD5{'a'}.hexdigest() == '0cc175b9c0f1b6a831c399e269772661'
		assert MD5{'abc'}.hexdigest() == '900150983cd24fb0d6963f7d28e17f72'
		assert MD5{'message digest'}.hexdigest() == 'f96b697d7cb7938d525a2f31aaf161d0'
		assert MD5{'abcdefghijklmnopqrstuvwxyz'}.hexdigest() == 'c3fcd3d76192e4007dfb496cca67e13b'
		assert MD5{'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'}.hexdigest() == 'd174ab98d277d9f5a5611c2c9f419d9f'
		assert MD5{'12345678901234567890123456789012345678901234567890123456789012345678901234567890'}.hexdigest() == '57edf4a22be3c955ac49da2e2107b67a'
		assert MD5{'1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890'}.hexdigest() == 'fdacad297f72956e0619002cecffc8e3'
	}
	println('took: ${sw.elapsed().milliseconds()} ms')
}
