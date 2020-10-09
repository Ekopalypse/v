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
fn aux_f(x u32, y u32, z u32) u32 { return (x & y) | ((~x) & z) }

fn aux_g(x u32, y u32, z u32) u32 { return (x & z) | (y & (~z)) }

fn aux_h(x u32, y u32, z u32) u32 { return x ^ y ^ z }

fn aux_i(x u32, y u32, z u32) u32 { return y ^ (x | (~z)) }

fn rotate_left(x u32, n u32) u32 { return (x << n) | (x >> (32-n)) }

// Instead of having FF GG HH and II functions we define one aux_x function
// and call the respective aux_... function by providing the function as parameter
fn aux_x(f fn(u32, u32, u32) u32, a u32, b u32, c u32, d u32, mi u32, s u32, t u32) u32 {
    mut result := u32(0)
    result += a + f(b, c, d) + mi + t
    result = rotate_left(result, s)
    result += b
    return result
}

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
        a = aux_x(aux_f, a, b, c, d, block.u32_arr[0],   7, 0xD76AA478)
        d = aux_x(aux_f, d, a, b, c, block.u32_arr[1],  12, 0xE8C7B756)
        c = aux_x(aux_f, c, d, a, b, block.u32_arr[2],  17, 0x242070DB)
        b = aux_x(aux_f, b, c, d, a, block.u32_arr[3],  22, 0xC1BDCEEE)
        a = aux_x(aux_f, a, b, c, d, block.u32_arr[4],   7, 0xF57C0FAF)
        d = aux_x(aux_f, d, a, b, c, block.u32_arr[5],  12, 0x4787C62A)
        c = aux_x(aux_f, c, d, a, b, block.u32_arr[6],  17, 0xA8304613)
        b = aux_x(aux_f, b, c, d, a, block.u32_arr[7],  22, 0xFD469501)
        a = aux_x(aux_f, a, b, c, d, block.u32_arr[8],   7, 0x698098D8)
        d = aux_x(aux_f, d, a, b, c, block.u32_arr[9],  12, 0x8B44F7AF)
        c = aux_x(aux_f, c, d, a, b, block.u32_arr[10], 17, 0xFFFF5BB1)
        b = aux_x(aux_f, b, c, d, a, block.u32_arr[11], 22, 0x895CD7BE)
        a = aux_x(aux_f, a, b, c, d, block.u32_arr[12],  7, 0x6B901122)
        d = aux_x(aux_f, d, a, b, c, block.u32_arr[13], 12, 0xFD987193)
        c = aux_x(aux_f, c, d, a, b, block.u32_arr[14], 17, 0xA679438E)
        b = aux_x(aux_f, b, c, d, a, block.u32_arr[15], 22, 0x49B40821)

	// Round 2.
        a = aux_x(aux_g, a, b, c, d, block.u32_arr[1],   5, 0xF61E2562)
        d = aux_x(aux_g, d, a, b, c, block.u32_arr[6],   9, 0xC040B340)
        c = aux_x(aux_g, c, d, a, b, block.u32_arr[11], 14, 0x265E5A51)
        b = aux_x(aux_g, b, c, d, a, block.u32_arr[0],  20, 0xE9B6C7AA)
        a = aux_x(aux_g, a, b, c, d, block.u32_arr[5],   5, 0xD62F105D)
        d = aux_x(aux_g, d, a, b, c, block.u32_arr[10],  9, 0x02441453)
        c = aux_x(aux_g, c, d, a, b, block.u32_arr[15], 14, 0xD8A1E681)
        b = aux_x(aux_g, b, c, d, a, block.u32_arr[4],  20, 0xE7D3FBC8)
        a = aux_x(aux_g, a, b, c, d, block.u32_arr[9],   5, 0x21E1CDE6)
        d = aux_x(aux_g, d, a, b, c, block.u32_arr[14],  9, 0xC33707D6)
        c = aux_x(aux_g, c, d, a, b, block.u32_arr[3],  14, 0xF4D50D87)
        b = aux_x(aux_g, b, c, d, a, block.u32_arr[8],  20, 0x455A14ED)
        a = aux_x(aux_g, a, b, c, d, block.u32_arr[13],  5, 0xA9E3E905)
        d = aux_x(aux_g, d, a, b, c, block.u32_arr[2],   9, 0xFCEFA3F8)
        c = aux_x(aux_g, c, d, a, b, block.u32_arr[7],  14, 0x676F02D9)
        b = aux_x(aux_g, b, c, d, a, block.u32_arr[12], 20, 0x8D2A4C8A)

	// Round 3.
        a = aux_x(aux_h, a, b, c, d, block.u32_arr[5],   4, 0xFFFA3942)
        d = aux_x(aux_h, d, a, b, c, block.u32_arr[8],  11, 0x8771F681)
        c = aux_x(aux_h, c, d, a, b, block.u32_arr[11], 16, 0x6D9D6122)
        b = aux_x(aux_h, b, c, d, a, block.u32_arr[14], 23, 0xFDE5380C)
        a = aux_x(aux_h, a, b, c, d, block.u32_arr[1],   4, 0xA4BEEA44)
        d = aux_x(aux_h, d, a, b, c, block.u32_arr[4],  11, 0x4BDECFA9)
        c = aux_x(aux_h, c, d, a, b, block.u32_arr[7],  16, 0xF6BB4B60)
        b = aux_x(aux_h, b, c, d, a, block.u32_arr[10], 23, 0xBEBFBC70)
        a = aux_x(aux_h, a, b, c, d, block.u32_arr[13],  4, 0x289B7EC6)
        d = aux_x(aux_h, d, a, b, c, block.u32_arr[0], 	11, 0xEAA127FA)
        c = aux_x(aux_h, c, d, a, b, block.u32_arr[3], 	16, 0xD4EF3085)
        b = aux_x(aux_h, b, c, d, a, block.u32_arr[6], 	23, 0x04881D05)
        a = aux_x(aux_h, a, b, c, d, block.u32_arr[9], 	 4, 0xD9D4D039)
        d = aux_x(aux_h, d, a, b, c, block.u32_arr[12], 11, 0xE6DB99E5)
        c = aux_x(aux_h, c, d, a, b, block.u32_arr[15], 16, 0x1FA27CF8)
        b = aux_x(aux_h, b, c, d, a, block.u32_arr[2],  23, 0xC4AC5665)


	// Round 4.
        a = aux_x(aux_i, a, b, c, d, block.u32_arr[0],   6, 0xF4292244)
        d = aux_x(aux_i, d, a, b, c, block.u32_arr[7],  10, 0x432AFF97)
        c = aux_x(aux_i, c, d, a, b, block.u32_arr[14], 15, 0xAB9423A7)
        b = aux_x(aux_i, b, c, d, a, block.u32_arr[5],  21, 0xFC93A039)
        a = aux_x(aux_i, a, b, c, d, block.u32_arr[12],  6, 0x655B59C3)
        d = aux_x(aux_i, d, a, b, c, block.u32_arr[3],  10, 0x8F0CCC92)
        c = aux_x(aux_i, c, d, a, b, block.u32_arr[10], 15, 0xFFEFF47D)
        b = aux_x(aux_i, b, c, d, a, block.u32_arr[1],  21, 0x85845DD1)
        a = aux_x(aux_i, a, b, c, d, block.u32_arr[8],   6, 0x6FA87E4F)
        d = aux_x(aux_i, d, a, b, c, block.u32_arr[15], 10, 0xFE2CE6E0)
        c = aux_x(aux_i, c, d, a, b, block.u32_arr[6],  15, 0xA3014314)
        b = aux_x(aux_i, b, c, d, a, block.u32_arr[13], 21, 0x4E0811A1)
        a = aux_x(aux_i, a, b, c, d, block.u32_arr[4],   6, 0xF7537E82)
        d = aux_x(aux_i, d, a, b, c, block.u32_arr[11], 10, 0xBD3AF235)
        c = aux_x(aux_i, c, d, a, b, block.u32_arr[2],  15, 0x2AD7D2BB)
        b = aux_x(aux_i, b, c, d, a, block.u32_arr[9],  21, 0xEB86D391)

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
	for _ in 0..10000 {
		mut md5 := MD5 {''}
		mut result := md5.hexdigest()
		assert result == 'd41d8cd98f00b204e9800998ecf8427e'

		md5 = MD5 {'a'}
		result = md5.hexdigest()
		assert result == '0cc175b9c0f1b6a831c399e269772661'

		md5 = MD5 {'abc'}
		result = md5.hexdigest()
		assert result == '900150983cd24fb0d6963f7d28e17f72'

		md5 = MD5 {'message digest'}
		result = md5.hexdigest()
		assert result == 'f96b697d7cb7938d525a2f31aaf161d0'

		md5 = MD5 {'abcdefghijklmnopqrstuvwxyz'}
		result = md5.hexdigest()
		assert result == 'c3fcd3d76192e4007dfb496cca67e13b'

		md5 = MD5 {'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'}
		result = md5.hexdigest()
		assert result == 'd174ab98d277d9f5a5611c2c9f419d9f'

		md5 = MD5 {'12345678901234567890123456789012345678901234567890123456789012345678901234567890'}
		result = md5.hexdigest()
		assert result == '57edf4a22be3c955ac49da2e2107b67a'

		md5 = MD5 {'1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890'}
		result = md5.hexdigest()
		assert result == 'fdacad297f72956e0619002cecffc8e3'

	}
	println('took: ${sw.elapsed().nanoseconds()}ns')
}
