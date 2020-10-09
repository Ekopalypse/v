// Copyright (c) 2019-2020 Alexander Medvednikov. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
import time
import crypto.md5

fn test_crypto_md5() {
	sw := time.new_stopwatch({})
	for _ in 0..100000 {
		assert md5.sum(''.bytes()).hex() == 'd41d8cd98f00b204e9800998ecf8427e'
		assert md5.sum('a'.bytes()).hex() == '0cc175b9c0f1b6a831c399e269772661'
		assert md5.sum('abc'.bytes()).hex() == '900150983cd24fb0d6963f7d28e17f72'
		assert md5.sum('message digest'.bytes()).hex() == 'f96b697d7cb7938d525a2f31aaf161d0'
		
		assert md5.sum('abcdefghijklmnopqrstuvwxyz'.bytes()).hex() == 'c3fcd3d76192e4007dfb496cca67e13b'
		assert md5.sum('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'.bytes()).hex() == 'd174ab98d277d9f5a5611c2c9f419d9f'
		assert md5.sum('12345678901234567890123456789012345678901234567890123456789012345678901234567890'.bytes()).hex() == '57edf4a22be3c955ac49da2e2107b67a'
		assert md5.sum('1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890'.bytes()).hex() == 'fdacad297f72956e0619002cecffc8e3'
	}
	println('took: ${sw.elapsed().milliseconds()} ms')
}
