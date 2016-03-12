//1
window.onload = function() {

	//加载完毕后添加按钮事件
	document.getElementById("encrypt").onclick = function() {
		chrome.tabs.query({
			active: true,
			currentWindow: true
		}, function(tabs) {
			chrome.tabs.sendMessage(tabs[0].id, {
				instruction: "toBackground",
				mode: "UIencrypt"
			}, function(response) {
				//
			});
		});
	}

	document.getElementById("decrypt").onclick = function() {
		chrome.tabs.query({
			active: true,
			currentWindow: true
		}, function(tabs) {
			chrome.tabs.sendMessage(tabs[0].id, {
				instruction: "toBackground",
				mode: "UIdecrypt"
			}, function(response) {
				//
			});
		});
	}

}


/*
chrome.runtime.onMessage.addListener(
	function(request, sender, sendResponse) {
		console.log(sender.tab ?
			"f from a content script:" + sender.tab.url :
			"f from the extension");
		if (request.greeting == "hello")
			console.log(1);
		sendResponse({
			
		});
	}
);
*/