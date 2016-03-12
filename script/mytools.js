function replaceCharAt(source, pos, newChar) {
	if (pos < 0 || pos >= source.length || source.length == 0) {
		console.error("the function 'replaceCharAt in mytools.js has unexcepted parameter");
		return null;
	}
	var sFrontPart = source.substr(0, pos);
	var sTailPart = source.substr(pos + 1, source.length);
	return sFrontPart + newChar + sTailPart;
}