/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
/*  AES implementation in JavaScript (c) Chris Veness 2005-2012          */
/*     - see http://csrc.nist.gov/publications/PubsFIPS.html#197                */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */



/*
 * 
 * 注意：目前只支持最长16字节的输入和密钥
 * 
 */
var AES = {};
// AES namespace

/**
 * AES encrypt function: encrypt 'input' state with Rijndael algorithm
 *   applies Nr rounds (10/12/14) using key schedule w for 'add round key' stage
 * 
 * @param {Number[]} input 16-byte (128-bit) input state array
 * @param {Number[][]} w   Key schedule as 2D byte-array (Nr+1 x Nb bytes)
 * @returns {Number[]}     Encrypted output state array
 */
AES.encrypt = function(input, w) {// main Cipher function [��5.1]
	var Nb = 4;
	// block size (in words): no of columns in state (fixed at 4 for AES)
	var Nr = w.length / Nb - 1;
	// no of rounds: 10/12/14 for 128/192/256-bit keys

	var state = [[], [], [], []];
	// initialise 4xNb byte-array 'state' with input [��3.4]
	for (var i = 0; i < 4 * Nb; i++)
		state[i%4][Math.floor(i / 4)] = input[i];

	state = AES.addRoundKey(state, w, 0, Nb);

	for (var round = 1; round < Nr; round++) {
		state = AES.subBytes(state, Nb);
		state = AES.shiftRows(state, Nb);
		state = AES.mixColumns(state, Nb);
		state = AES.addRoundKey(state, w, round, Nb);
	}
	state = AES.subBytes(state, Nb);
	state = AES.shiftRows(state, Nb);
	state = AES.addRoundKey(state, w, Nr, Nb);

	var output = new Array(4 * Nb);
	// 按列主序的方式把矩阵转换成为字符串
	for (var i = 0; i < 4 * Nb; i++)
		output[i] = state[i%4][Math.floor(i / 4)];
	return output;
}

AES.UIencrypt = function(plaintext, password) {//只支持128比特秘钥长度
	var ptBytes = AES.strToMatrix(plaintext);
	var pwBytes = AES.strToMatrix(password);
	var w = AES.keyExpansion(pwBytes);
	var encry = AES.encrypt(ptBytes, w);
	return encry.map(AES.toHex).join("");
}

AES.decrypt = function(state, w) {// main Cipher function [��5.1]
	var Nb = 4;
	// block size (in words): no of columns in state (fixed at 4 for AES)
	var Nr = w.length / Nb - 1;
	// no of rounds: 10/12/14 for 128/192/256-bit keys
	state = AES.addRoundKey(state, w, Nr, Nb);
	for (var round = Nr - 1; round > 0; round--) {
		state = AES.invSubBytes(state, Nb);
		state = AES.invShiftRows(state, Nb);
		state = AES.invMixColumns(state, Nb);
		state = AES.invAddRoundKey(state, w, round, Nb);
	}
	state = AES.invSubBytes(state, Nb);
	state = AES.invShiftRows(state, Nb);
	state = AES.addRoundKey(state, w, 0, Nb);

	//此时state是4*Nb大小的矩阵，要将其转化为一维数组，数组中存放明文即ascii码
	var result = new Array(16);
	for (var i = 0; i < 4; i++) {
		for (var j = 0; j < 4; j++)
			result[i * 4 + j] = state[j][i];
	}

	return result;
}

AES.UIdecrypt = function(encrypted, password) {
	var pwBytes = AES.strToMatrix(password);
	var w = AES.keyExpansion(pwBytes);
	var state = AES.hexToState(encrypted);
	var plaintext = AES.decrypt(state, w);
	return plaintext.map(function(x) {
		return String.fromCharCode(x);
	}).join("");
}
/**
 * Perform Key Expansion to generate a Key Schedule
 *
 * @param {Number[]} key Key as 16/24/32-byte array
 * @returns {Number[][]} Expanded key schedule as 2D byte-array (Nr+1 x Nb bytes)
 */
AES.keyExpansion = function(key) {// generate Key Schedule (byte-array Nr+1 x Nb) from Key [��5.2]
	var Nb = 4;
	// block size (in words): no of columns in state (fixed at 4 for AES)
	var Nk = key.length / 4// key length (in words): 4/6/8 for 128/192/256-bit keys
	var Nr = Nk + 6;
	// no of rounds: 10/12/14 for 128/192/256-bit keys

	var w = new Array(Nb * (Nr + 1));
	var temp = new Array(4);

	for (var i = 0; i < Nk; i++) {
		var r = [key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]];
		w[i] = r;
	}

	for (var i = Nk; i < (Nb * (Nr + 1)); i++) {
		w[i] = new Array(4);
		for (var t = 0; t < 4; t++)
			temp[t] = w[i-1][t];
		if (i % Nk == 0) {
			temp = AES.subWord(AES.rotWord(temp));
			for (var t = 0; t < 4; t++)
				temp[t] ^=AES.rCon[i/Nk][t];
		} else if (Nk > 6 && i % Nk == 4) {
			temp = AES.subWord(temp);
		}
		for (var t = 0; t < 4; t++)
			w[i][t] = w[i-Nk][t] ^ temp[t];
	}

	return w;
}
/*
* ---- remaining routines are private, not called externally ----
*/

AES.subBytes = function(s, Nb) {// (cipher) apply SBox to state S [��5.1.1]
	for (var r = 0; r < 4; r++) {
		for (var c = 0; c < Nb; c++) {
			s[r][c] = AES.SBox[s[r][c]];
		}
	}
	return s;
}

AES.invSubBytes = function(s, Nb) {
	for (var r = 0; r < 4; r++) {
		for (var c = 0; c < Nb; c++) {
			s[r][c] = AES.invSBox[s[r][c]];
		}
	}
	return s;
};

AES.shiftRows = function(s, Nb) {// (cipher) shift row r of state S left by r bytes [��5.1.2]
	var t = new Array(4);
	for (var r = 1; r < 4; r++) {
		for (var c = 0; c < 4; c++) {
			t[c] = s[r][(c + r) % Nb];
			// shift into temp copy
		}
		for (var c = 0; c < 4; c++) {
			s[r][c] = t[c];
			// and copy back
		}
	}// note that this will work for Nb=4,5,6, but not 7,8 (always 4 for AES):
	return s;
	// see asmaes.sourceforge.net/rijndael/rijndaelImplementation.pdf
}

AES.invShiftRows = function(s, Nb) {
	var t = new Array(4);
	for (var r = 1; r < 4; r++) {
		for (var c = 0; c < 4; c++) {
			t[c] = s[r][(c + Nb - r) % Nb];
			// shift into temp copy
		}
		for (var c = 0; c < 4; c++) {
			s[r][c] = t[c];
			// and copy back
		}
	}// note that this will work for Nb=4,5,6, but not 7,8 (always 4 for AES):
	return s;
	// see asmaes.sourceforge.net/rijndael/rijndaelImplementation.pdf
}

AES.mixColumns = function(s, Nb) {// combine bytes of each col of state S [��5.1.3]
	var a = new Array(4);
	// 'a' is a copy of the current column from 's'
	var b = new Array(4);
	// 'b' is a?{02} in GF(2^8)
	for (var j = 0; j < 4; j++) {
		for (var i = 0; i < 4; i++) {
			a[i] = s[i][j];
			b[i] = s[i][j] & 0x80 ? s[i][j] << 1 ^ 0x011b : s[i][j] << 1;
			//即密码学课本上56页的运算xtime，即m=100011011的GF(2^8)中的乘2运算
		}
		// a[n] ^ b[n] is a?{03} in GF(2^8)
		s[0][j] = b[0] ^ a[1] ^ b[1] ^ a[2] ^ a[3];
		// 2*a0 + 3*a1 + a2 + a3
		s[1][j] = a[0] ^ b[1] ^ a[2] ^ b[2] ^ a[3];
		// a0 * 2*a1 + 3*a2 + a3
		s[2][j] = a[0] ^ a[1] ^ b[2] ^ a[3] ^ b[3];
		// a0 + a1 + 2*a2 + 3*a3
		s[3][j] = a[0] ^ b[0] ^ a[1] ^ a[2] ^ b[3];
		// 3*a0 + a1 + a2 + 2*a3
	}
	return s;
}

AES.invMixColumns = function(s, Nb) {
	var a = new Array(4);
	// 'a' is a copy of the current column from 's'
	var b = new Array(4);
	// 'b' is a?{02} in GF(2^8)
	var c = new Array(4);
	var d = new Array(4);
	for (var j = 0; j < 4; j++) {
		for (var i = 0; i < 4; i++) {
			a[i] = s[i][j];
			b[i] = a[i] & 0x80 ? a[i] << 1 ^ 0x011b : a[i] << 1;
			//GF(2^8)上的2*a[i]
			c[i] = b[i] & 0x80 ? b[i] << 1 ^ 0x011b : b[i] << 1;
			//GF(2^8)上的4*a[i]
			d[i] = c[i] & 0x80 ? c[i] << 1 ^ 0x011b : c[i] << 1;
			//GF(2^8)上的8*a[i]
		}
		//  in GF(2^8)
		s[0][j] = d[0] ^ c[0] ^ b[0] ^ d[1] ^ b[1] ^ a[1] ^ d[2] ^ c[2] ^ a[2] ^ d[3] ^ a[3];
		//a0 = oe*b0 + 0b*b1 + 0d*b2 + 09*b3
		s[1][j] = d[1] ^ c[1] ^ b[1] ^ d[2] ^ b[2] ^ a[2] ^ d[3] ^ c[3] ^ a[3] ^ d[0] ^ a[0];
		//a1= oe*b1 + 0b*b2 + 0d*b3 + 09*b0
		s[2][j] = d[2] ^ c[2] ^ b[2] ^ d[3] ^ b[3] ^ a[3] ^ d[0] ^ c[0] ^ a[0] ^ d[1] ^ a[1];
		//a2 = oe*b2 + 0b*b3 + 0d*b0 + 09*b1
		s[3][j] = d[3] ^ c[3] ^ b[3] ^ d[0] ^ b[0] ^ a[0] ^ d[1] ^ c[1] ^ a[1] ^ d[2] ^ a[2];
		//a3 = oe*b3 + 0b*b0 + 0d*b1 + 09*b2
	}
	return s;
}

AES.addRoundKey = function(state, w, rnd, Nb) {// xor Round Key into state S [��5.1.4]
	for (var r = 0; r < 4; r++) {
		for (var c = 0; c < Nb; c++) {
			state[r][c] ^=w[rnd*4+c][r];
			//state[r][c]
		}
	}

	return state;
}

AES.invAddRoundKey = function(state, w, rnd, Nb) {
	//其实是不需要密钥加的逆函数的，实际是把对应的轮密钥经过列混合函数再进行密钥加
	//这个函数只是把这两个函数结合到了一起
	var wtemp = [[], [], [], []];
	for (var r = 0; r < 4; r++) {
		for (var c = 0; c < Nb; c++) {
			wtemp[c][r] = w[rnd*4+r][c];
		}
	}
	wtemp = AES.invMixColumns(wtemp, Nb);
	for (var r = 0; r < 4; r++) {
		for (var c = 0; c < Nb; c++) {
			state[r][c] ^=wtemp[r][c];
		}
	}
	return state;

}

AES.subWord = function(w) {// apply SBox to 4-byte word w
	for (var i = 0; i < 4; i++)
		w[i] = AES.SBox[w[i]];
	return w;
}

AES.rotWord = function(w) {// rotate 4-byte word w left by one byte
	var tmp = w[0];
	for (var i = 0; i < 3; i++)
		w[i] = w[i + 1];
	w[3] = tmp;
	return w;
}
// sBox is pre-computed multiplicative inverse in GF(2^8) used in subBytes and keyExpansion [��5.1.1]
AES.SBox = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16];

AES.invSBox = [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d];

// rCon is Round Constant used for the Key Expansion [1st col is 2^(r-1) in GF(2^8)] [��5.2]
AES.rCon = [[0x00, 0x00, 0x00, 0x00], [0x01, 0x00, 0x00, 0x00], [0x02, 0x00, 0x00, 0x00], [0x04, 0x00, 0x00, 0x00], [0x08, 0x00, 0x00, 0x00], [0x10, 0x00, 0x00, 0x00], [0x20, 0x00, 0x00, 0x00], [0x40, 0x00, 0x00, 0x00], [0x80, 0x00, 0x00, 0x00], [0x1b, 0x00, 0x00, 0x00], [0x36, 0x00, 0x00, 0x00]];

AES.toHex = function(x) {
	//把字符串中表示的十进制转化为字符串表示的十六进制
	var str = x.toString(16).toUpperCase();
	if (str.length == 1) {
		return "0" + str;
	} else {
		return str;
	}
}

AES.strToMatrix = function(str) {//把字符串转化为阵列，只支持128比特长度
	var nBits = 128;
	var nBytes = nBits / 8;
	var Bytes = new Array(nBytes);
	for (var i = 0; i < nBytes; i++) {// use 1st 16/24/32 chars of password for key
		Bytes[i] = isNaN(str.charCodeAt(i)) ? 0 : str.charCodeAt(i);
	}
	return Bytes;
}

AES.hexToState = function(str) {
	//把字符串表示的十六进制z转化为十进制表示的State矩阵
	var state = [[], [], [], []]
	var i;
	var j;
	for ( i = 0; i < 4; i++) {
		for ( j = 0; j < 4; j++)
			state[j][i] = parseInt(str.slice(2 * (4 * i + j), 2 * (4 * i + j) + 2).toString(10), 16);
	}
	return state;
}
