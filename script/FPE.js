//initialize


//TODO
//使用该模块之前，应进行字符串合法性监测，对字符集、及大小写进行检测


var FPE = {};
//允许加密字符集的大小，与允许的字符集
FPE.scale = 37;
FPE.dictionary = "abcdefghijklmnopqrstuvwxyz1234567890_";

/*
 * 注意！不区分大小写！
 * parameter dest: 已经处理好的dest字符串
 * parameter length：需要加密的长度
 *
 * TODO：调用此函数之前先调用FPE.checkStrLegitimacy检查输入字符串的合法性
 */
FPE.UIencrypt = function(plaintext) {
	var dest = FPE.getStringOffset(plaintext);
	var length = plaintext.length;
	return FPE.format(FPE.encrypt(dest));
}

FPE.encrypt = function(dest) {

	var len = dest.length;
	var length = Math.floor(len / 2);

	var left = new String();
	var right = new String();
	var middle = new String();

	//直接赋值给字符串ascii码为0x00的字符会失败，因为0x00在ascii中表示null，所以我采取这种方式幅值，先把字符串初始化为有意义的内容，再依次替换
	for (i = 0; i < 128; i++) {
		left = left.concat('a');
		right = right.concat('a');
	}
	for (i = 0; i < 512; i++) {
		middle = middle.concat('a');
	}

	for (loop = 0; loop < 6; loop++) {
		for (i = 0; i < 128; i++) {
			left = replaceCharAt(left, i, String.fromCharCode(0x00));
			right = replaceCharAt(right, i, String.fromCharCode(0x00));
		}
		for (i = 0; i < length; i++) {
			left = replaceCharAt(left, i, dest[i]);
		}
		for (i = 0; i < len - length; i++) {
			right = replaceCharAt(right, i, dest[i + length]);
		}

		/*********************伪随机函数完毕************************/
		for (i = 0; i < Math.floor(((len - length) / 16 + 1)); i++) {
			var plaintext = right.substr(16 * i, 16);
			password = FPE.getAESKey();
			var ptBytes = AES.strToMatrix(plaintext);
			var pwBytes = AES.strToMatrix(password);
			var w = AES.keyExpansion(pwBytes);
			var encry = AES.encrypt(ptBytes, w);

			for (j = 0; j < 16; j++) {
				//应该是直接复制给middle的,不过因为middle是字符串，为了方便以字符形式存放，便提前模scale了，这么做的可行性是由于在下一步也要模scale
				middle = replaceCharAt(middle, j, String.fromCharCode(encry[j] % FPE.scale));
			}

		}
		var srtValue;
		for (j = 0; j < length; j++) {
			srtValue = (FPE.charCodeAt(left[j]) + FPE.charCodeAt(middle[j])) % FPE.scale;
			left = replaceCharAt(left, j, String.fromCharCode(srtValue));
		}
		/*********************伪随机函数完毕************************/

		//输出部分,用于调试
		/*
		document.write(encry + "<BR>");
		for ( i = 0; i < 16; i++) {
			document.write(FPE.charCodeAt(left[i]) + "  ");
		}
		document.write("<BR>");
		*/
		//将右侧内容复制到左侧
		for (i = 0; i < len - length; i++) {
			dest = replaceCharAt(dest, i, right[i]);
		}
		//将处理完毕左侧的内容，复制到右侧
		for (i = 0; i < length; i++) {
			dest = replaceCharAt(dest, i + (len - length), left[i]);
		}
		//document.write("<br>");
	}

	/*
	for ( i = 0; i < 8; i++) {
		document.write(FPE.charCodeAt(dest[i]) + "  ");
	}
	document.write("<br><br>");
	*/
	return dest;
}

FPE.UIdecrypt = function(encrypted) {
		dest = FPE.getStringOffset(encrypted);
		return FPE.format(FPE.decrypt(dest));
	}
	/*
	 * parameter encrypted: 已经经过FPE加密的字符串
	 */
FPE.decrypt = function(dest) {
		len = dest.length;
		length = len - Math.floor(len / 2);
		var left = new String();
		var right = new String();
		var middle = new String();

		//直接赋值给字符串ascii码为0x00的字符会失败，因为0x00在ascii中表示null，所以我采取这种方式幅值，先把字符串初始化为有意义的内容，再依次替换
		for (i = 0; i < 128; i++) {
			left = left.concat('a');
			right = right.concat('a');
		}
		for (i = 0; i < 512; i++) {
			middle = middle.concat('a');
		}
		for (loop = 0; loop < 6; loop++) {
			for (i = 0; i < 128; i++) {
				left = replaceCharAt(left, i, String.fromCharCode(0x00));
				right = replaceCharAt(right, i, String.fromCharCode(0x00));
			}
			for (i = 0; i < length; i++) {
				//dest左半部分拷贝给left
				left = replaceCharAt(left, i, dest[i]);
			}
			for (i = 0; i < len - length; i++) {
				//dest右半部分拷贝给right
				right = replaceCharAt(right, i, dest[i + length]);
			}
			for (i = 0; i < 512; i++) {
				middle = replaceCharAt(middle, i, String.fromCharCode(0x00));
			}
			for (i = 0; i < Math.floor(((len - length) / 16 + 1)); i++) {
				var encrypted = left.substr(16 * i, 16);
				password = FPE.getAESKey();
				var ptBytes = AES.strToMatrix(encrypted);
				var pwBytes = AES.strToMatrix(password);
				var w = AES.keyExpansion(pwBytes);
				plaintext = AES.encrypt(ptBytes, w);

				for (j = 0; j < 16; j++) {
					//应该是直接复制给middle的,不过因为middle是字符串，为了方便以字符形式存放，便提前模scale了，这么做的可行性是由于在下一步也要scale
					middle = replaceCharAt(middle, j, String.fromCharCode(plaintext[j] % FPE.scale));
				}

			}
			var srtValue;
			for (j = 0; j < length; j++) {
				srtValue = FPE.charCodeAt(right[j]) - FPE.charCodeAt(middle[j]);
				while (srtValue < 0) {
					srtValue += FPE.scale;
				}
				right = replaceCharAt(right, j, String.fromCharCode(srtValue));
			}

			//输出部分,用于调试
			/*
			document.write(plaintext + "<BR>");
			for ( i = 0; i < 16; i++) {
				document.write(FPE.charCodeAt(left[i]) + "  ");
			}
			document.write("<BR>");
			*/
			//将右侧内容复制到左侧
			for (i = 0; i < len - length; i++) {
				dest = replaceCharAt(dest, i, right[i]);
			}
			//将处理完毕左侧的内容，复制到右侧
			for (i = 0; i < length; i++) {
				dest = replaceCharAt(dest, i + len - length, left[i]);
			}
			//document.write("<br>");
		}
		/*
		for ( i = 0; i < 8; i++) {
			document.write(FPE.charCodeAt(dest[i]) + "  ");
		}
		*/
		return dest;
	}
	/*
	 * 将字符转换成为允许加密字符集中的偏移量
	 * 目前只接受数字和字母且不区分大小写
	 * 此时char需要已经被转换成为小写字符
	 * 没有找到返回-1
	 */
FPE.getStringOffset = function(str) {
		var newstr = str;
		for (i = 0; i < str.length; i++) {
			newstr = replaceCharAt(newstr, i, String.fromCharCode(FPE.dictionary.indexOf(newstr[i])));
		}
		return newstr;
	}
	/*
	 * 取得FPE算法内置的AES的128比特密钥
	 */
FPE.getAESKey = function() {
	/*
	0xC3, 0x4C, 0x05, 0x2C, 0xC0, 0xDA, 0x8D, 0x73,
	0x45, 0x1A, 0xFE, 0x5F, 0x03, 0xBE, 0x29, 0x7F
	*/
	//预先填充长度
	key = "****************";

	key = key.replace("*", String.fromCharCode(0xC3));
	key = key.replace("*", String.fromCharCode(0x4C));
	key = key.replace("*", String.fromCharCode(0x05));
	key = key.replace("*", String.fromCharCode(0x2C));
	key = key.replace("*", String.fromCharCode(0xC0));
	key = key.replace("*", String.fromCharCode(0xDA));
	key = key.replace("*", String.fromCharCode(0x8D));
	key = key.replace("*", String.fromCharCode(0x73));

	key = key.replace("*", String.fromCharCode(0x45));
	key = key.replace("*", String.fromCharCode(0x1A));
	key = key.replace("*", String.fromCharCode(0xFE));
	key = key.replace("*", String.fromCharCode(0x5F));
	key = key.replace("*", String.fromCharCode(0x03));
	key = key.replace("*", String.fromCharCode(0xBE));
	key = key.replace("*", String.fromCharCode(0x29));
	key = key.replace("*", String.fromCharCode(0x7F));

	return key;
}

/*
 * 把隐式存放于字符串ascii码中的内容转换为显示的存放于字符串的字符值中
 * 该函数作用仅仅为便于程序猿查看内容，实际使用可以不用
 */
FPE.format = function(str) {
	var newstr = str;
	for (i = 0; i < str.length; i++) {
		newstr = replaceCharAt(newstr, i, FPE.dictionary.charAt(FPE.charCodeAt(str[i])));
	}
	return newstr;
}

FPE.charCodeAt = function(c) {
	//解决对不同浏览器之间的charCodeAt函数实现方式不同的问题
	if (navigator.appVersion.indexOf("Chrome") >= 0) {
		return c.charCodeAt();
	} else {
		return String.charCodeAt(c);
	}
}

FPE.checkStrLegitimacy = function(inputStr) {
	var lowerStr = inputStr.toLowerCase();
	for (var i = 0; i < lowerStr.length; i++) {
		if (FPE.dictionary.indexOf(lowerStr[i]) == -1) {
			return false;
		}
	}
	return true;
}