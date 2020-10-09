// md5 hash function implemented in v
// implementation based on https://tools.ietf.org/html/rfc1321
// and the book Applied Cryptography
import time

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
	message_bytes << [byte(0x80)]

	message_length := message_bytes.len
	mod_result := message_length % 64
	pad_length := if mod_result < 56 { 56 - mod_result } else { 120 - mod_result }

	if pad_length > 0 {
		message_bytes << []byte{len:pad_length, init:0}
	}

	// Step 2. Append original length - always
	mut mlv := U64Value{}
	mlv.xu64 = u64(original_length)
	for b in mlv.bytes { message_bytes << b }

	// Step 3. Initialize MD Buffer
	mut a := u32(0x67452301)
	mut b := u32(0xEFCDAB89)
	mut c := u32(0x98BADCFE)
	mut d := u32(0x10325476)

	// Step 4. Process Message in 16-Word Blocks. Here a word is meant to be a u32
	mut block := WordBlock{}
	for i in 0..message_bytes.len/64 {
		unsafe {
			C.memcpy(block.bytes, message_bytes[i*64..i*64+64].data, 64)
		}

	// save current state
		mut aa := a
		mut bb := b
		mut cc := c
		mut dd := d

	// Round 1.
        a = rotate_left(a + ff(b, c, d) + block.u32_arr[0]  + u32(0xD76AA478),  7) + b
        d = rotate_left(d + ff(a, b, c) + block.u32_arr[1]  + u32(0xE8C7B756), 12) + a
        c = rotate_left(c + ff(d, a, b) + block.u32_arr[2]  + u32(0x242070DB), 17) + d
        b = rotate_left(b + ff(c, d, a) + block.u32_arr[3]  + u32(0xC1BDCEEE), 22) + c
        a = rotate_left(a + ff(b, c, d) + block.u32_arr[4]  + u32(0xF57C0FAF),  7) + b
        d = rotate_left(d + ff(a, b, c) + block.u32_arr[5]  + u32(0x4787C62A), 12) + a
        c = rotate_left(c + ff(d, a, b) + block.u32_arr[6]  + u32(0xA8304613), 17) + d
        b = rotate_left(b + ff(c, d, a) + block.u32_arr[7]  + u32(0xFD469501), 22) + c
        a = rotate_left(a + ff(b, c, d) + block.u32_arr[8]  + u32(0x698098D8),  7) + b
        d = rotate_left(d + ff(a, b, c) + block.u32_arr[9]  + u32(0x8B44F7AF), 12) + a
        c = rotate_left(c + ff(d, a, b) + block.u32_arr[10] + u32(0xFFFF5BB1), 17) + d
        b = rotate_left(b + ff(c, d, a) + block.u32_arr[11] + u32(0x895CD7BE), 22) + c
        a = rotate_left(a + ff(b, c, d) + block.u32_arr[12] + u32(0x6B901122),  7) + b
        d = rotate_left(d + ff(a, b, c) + block.u32_arr[13] + u32(0xFD987193), 12) + a
        c = rotate_left(c + ff(d, a, b) + block.u32_arr[14] + u32(0xA679438E), 17) + d
        b = rotate_left(b + ff(c, d, a) + block.u32_arr[15] + u32(0x49B40821), 22) + c

	// Round 2.
        a = rotate_left(a + fg(b, c, d) + block.u32_arr[1]  + u32(0xF61E2562),  5) + b
        d = rotate_left(d + fg(a, b, c) + block.u32_arr[6]  + u32(0xC040B340),  9) + a
        c = rotate_left(c + fg(d, a, b) + block.u32_arr[11] + u32(0x265E5A51), 14) + d
        b = rotate_left(b + fg(c, d, a) + block.u32_arr[0]  + u32(0xE9B6C7AA), 20) + c
        a = rotate_left(a + fg(b, c, d) + block.u32_arr[5]  + u32(0xD62F105D),  5) + b
        d = rotate_left(d + fg(a, b, c) + block.u32_arr[10] + u32(0x02441453),  9) + a
        c = rotate_left(c + fg(d, a, b) + block.u32_arr[15] + u32(0xD8A1E681), 14) + d
        b = rotate_left(b + fg(c, d, a) + block.u32_arr[4]  + u32(0xE7D3FBC8), 20) + c
        a = rotate_left(a + fg(b, c, d) + block.u32_arr[9]  + u32(0x21E1CDE6),  5) + b
        d = rotate_left(d + fg(a, b, c) + block.u32_arr[14] + u32(0xC33707D6),  9) + a
        c = rotate_left(c + fg(d, a, b) + block.u32_arr[3]  + u32(0xF4D50D87), 14) + d
        b = rotate_left(b + fg(c, d, a) + block.u32_arr[8]  + u32(0x455A14ED), 20) + c
        a = rotate_left(a + fg(b, c, d) + block.u32_arr[13] + u32(0xA9E3E905),  5) + b
        d = rotate_left(d + fg(a, b, c) + block.u32_arr[2]  + u32(0xFCEFA3F8),  9) + a
        c = rotate_left(c + fg(d, a, b) + block.u32_arr[7]  + u32(0x676F02D9), 14) + d
        b = rotate_left(b + fg(c, d, a) + block.u32_arr[12] + u32(0x8D2A4C8A), 20) + c

	// Round 3.
        a = rotate_left(a + fh(b, c, d) + block.u32_arr[5]  + u32(0xFFFA3942),  4) + b
        d = rotate_left(d + fh(a, b, c) + block.u32_arr[8]  + u32(0x8771F681), 11) + a
        c = rotate_left(c + fh(d, a, b) + block.u32_arr[11] + u32(0x6D9D6122), 16) + d
        b = rotate_left(b + fh(c, d, a) + block.u32_arr[14] + u32(0xFDE5380C), 23) + c
        a = rotate_left(a + fh(b, c, d) + block.u32_arr[1]  + u32(0xA4BEEA44),  4) + b
        d = rotate_left(d + fh(a, b, c) + block.u32_arr[4]  + u32(0x4BDECFA9), 11) + a
        c = rotate_left(c + fh(d, a, b) + block.u32_arr[7]  + u32(0xF6BB4B60), 16) + d
        b = rotate_left(b + fh(c, d, a) + block.u32_arr[10] + u32(0xBEBFBC70), 23) + c
        a = rotate_left(a + fh(b, c, d) + block.u32_arr[13] + u32(0x289B7EC6),  4) + b
        d = rotate_left(d + fh(a, b, c) + block.u32_arr[0]  + u32(0xEAA127FA), 11) + a
        c = rotate_left(c + fh(d, a, b) + block.u32_arr[3]  + u32(0xD4EF3085), 16) + d
        b = rotate_left(b + fh(c, d, a) + block.u32_arr[6]  + u32(0x04881D05), 23) + c
        a = rotate_left(a + fh(b, c, d) + block.u32_arr[9]  + u32(0xD9D4D039),  4) + b
        d = rotate_left(d + fh(a, b, c) + block.u32_arr[12] + u32(0xE6DB99E5), 11) + a
        c = rotate_left(c + fh(d, a, b) + block.u32_arr[15] + u32(0x1FA27CF8), 16) + d
        b = rotate_left(b + fh(c, d, a) + block.u32_arr[2]  + u32(0xC4AC5665), 23) + c


	// Round 4.
        a = rotate_left(a + fi(b, c, d) + block.u32_arr[0]  + u32(0xF4292244),  6) + b
        d = rotate_left(d + fi(a, b, c) + block.u32_arr[7]  + u32(0x432AFF97), 10) + a
        c = rotate_left(c + fi(d, a, b) + block.u32_arr[14] + u32(0xAB9423A7), 15) + d
        b = rotate_left(b + fi(c, d, a) + block.u32_arr[5]  + u32(0xFC93A039), 21) + c
        a = rotate_left(a + fi(b, c, d) + block.u32_arr[12] + u32(0x655B59C3),  6) + b
        d = rotate_left(d + fi(a, b, c) + block.u32_arr[3]  + u32(0x8F0CCC92), 10) + a
        c = rotate_left(c + fi(d, a, b) + block.u32_arr[10] + u32(0xFFEFF47D), 15) + d
        b = rotate_left(b + fi(c, d, a) + block.u32_arr[1]  + u32(0x85845DD1), 21) + c
        a = rotate_left(a + fi(b, c, d) + block.u32_arr[8]  + u32(0x6FA87E4F),  6) + b
        d = rotate_left(d + fi(a, b, c) + block.u32_arr[15] + u32(0xFE2CE6E0), 10) + a
        c = rotate_left(c + fi(d, a, b) + block.u32_arr[6]  + u32(0xA3014314), 15) + d
        b = rotate_left(b + fi(c, d, a) + block.u32_arr[13] + u32(0x4E0811A1), 21) + c
        a = rotate_left(a + fi(b, c, d) + block.u32_arr[4]  + u32(0xF7537E82),  6) + b
        d = rotate_left(d + fi(a, b, c) + block.u32_arr[11] + u32(0xBD3AF235), 10) + a
        c = rotate_left(c + fi(d, a, b) + block.u32_arr[2]  + u32(0x2AD7D2BB), 15) + d
        b = rotate_left(b + fi(c, d, a) + block.u32_arr[9]  + u32(0xEB86D391), 21) + c

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

	for b_yte in m_digest.bytes {
		msg_digest << b_yte
	}

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
