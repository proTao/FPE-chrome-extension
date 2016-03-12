//2'
background = {};

chrome.runtime.onMessage.addListener(
	function(request, sender, sendResponse) {
		var encrypted_array = background.batchEncryptByFPE(request.input, request.mode);
		sendResponse(encrypted_array);
	}
);

background.batchEncryptByFPE = function(string_array, mode) {
	var encrypted_array = [];
	var fun = FPE[mode];
	for(var i = 0; i < string_array.length; i++) {
		encrypted_array.push(fun(string_array[i]));
	}
	return encrypted_array;
}