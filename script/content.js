content = {};

//设为全局变量省得函数之间传递
content.txt_and_pwd_element = [];

content.toBackground = function(mode) {
	content.txt_and_pwd_element = content.getTxtAndPwdElement();
	content.popupDialog(mode);
}




content.getTxtAndPwdElement = function() {
	//getElementsByTagName的返回值不是数组，W3C的标准是一个NodeList
	var input_element = document.getElementsByTagName('input');
	content.txt_and_pwd_element = [];
	for (var i = 0; i < input_element.length; i++) {
		if ((input_element[i].getAttribute("type") == "text") ||
			(input_element[i].getAttribute("type") == "password")) {
			//如果该input元素是text类型或者是是password类型，就将它加入至要返回的结果中
			content.txt_and_pwd_element.push(input_element[i]);
		}
	}

	//就是因为qq邮箱网页版登陆界面，这奇葩非要用iframe，我还得在这加代码，处理表单在iframe中的情况

	// 目前的问题，加上这段代码有的网页都处理了两遍
	/*
	if (window && window.frames && window.frames.length) {
		var iframe_doc = window.frames.document;
		input_element = iframe_doc.getElementsByTagName('input');
		for (var i = 0; i < input_element.length; i++) {
			if ((input_element[i].getAttribute("type") == "text") ||
				(input_element[i].getAttribute("type") == "password")) {
				//如果该input元素是text类型或者是是password类型，就将它加入至要返回的结果中
				content.txt_and_pwd_element.push(input_element[i]);
			}
		}
	}
	*/

	return content.txt_and_pwd_element;
}

content.getInputElementValue = function(input_array) {
	txt_array = [];
	for(var i = 0; i<input_array.length; i++) {
		txt_array.push(input_array[i].value);
	}
	return txt_array;
}

content.popupDialog = function(mode) {
	//TODO绑定事件
	var close_button = $("<input id='btnClose' type='button'  value='ok'></input>");
	var inner_div = $("<div class='pop-box-body'></div>");
	var inner_content = $("<form id='need-encrypted'></form>");

	//需要生成复选框
	for (var i = 0; i < content.txt_and_pwd_element.length; i++) {
		if(content.txt_and_pwd_element[i].value != "") {
			inner_content.html(inner_content.html() +
				"<input name='plaintext' type='checkbox' value='' />" +
				content.txt_and_pwd_element[i].value + 
				"<br>");
		} else {
			content.txt_and_pwd_element.splice(i,1);
			i--;//因为splice函数会改变数组的length，删除一个元素后下个循环还要检查当前下标的元素
		}
	}

	if(inner_content.html() == "") {
		//说明表单的txt和password都是空的
		inner_content.html("please input username and password");
	}
	inner_div.append(inner_content);
	inner_div.append(close_button);
	var outer_div = $("<div id='pop-div' style='width: 300px;'' class='pop-box'>  ");
	outer_div.append($("<h4>please choose what you want to encrypt</h4>")).append(inner_div);
	var dialog = $("<form id='pop-form'></form>");
	dialog.append(outer_div);
	if($("body>#pop-form").length != 0) {
		$("body>#pop-form").remove();
	}
	$("body").append(dialog);

	/*******************截止至此，弹出窗体html元素创建完毕,为按钮绑定事件**********************/
	close_button.bind("click",mode,content.chooseAndCloseDialog);
	content.popupDiv('pop-div');
}

content.popupDiv = function(div_id) {
	var div_obj = $("#" + div_id);
	var windowWidth = document.body.clientWidth;
	var windowHeight = document.body.clientHeight;
	var popupHeight = div_obj.height();
	var popupWidth = div_obj.width();
	//添加并显示遮罩层   
	$("<div id='mask'></div>")
		.addClass("mask")
		.css("z-index","9998")
		.width(/*windowWidth + */window.screen.availWidth)
		.height(windowHeight + document.body.scrollHeight)
		.click(function() { 
			//暂时不给用户其他选择，让用户只能选择点击对话框的按钮关闭
			//content.chooseAndCloseDialog(div_id);
		})
		.appendTo("body")
		.fadeIn(200);


	div_obj.css({
			"position": "absolute"
		})
		.animate({
			left: window.screen.availWidth / 2 - popupWidth / 2,
			top: window.screen.availHeight / 2 - popupHeight / 2,
			opacity: "show"
		}, "slow");

}

content.chooseAndCloseDialog = function(mode) {
	//获得用户的勾选结果，并将用户没有勾选的内容移出txt_and_pwd_element数组，方便加密后更改
	var checkbox = $("body>form #need-encrypted")[0];
	var deleted_count = 0;
	for (var i = 0; i - deleted_count < content.txt_and_pwd_element.length; i++) {
		if (checkbox[i].checked == false) {
			content.txt_and_pwd_element.splice(i - deleted_count, 1);
			deleted_count++; //后台的数组删除了元素但是网页上显示的checkbox没有变，所以checkbox的下标不能减
		}
	}

	//已经获得了用户的勾选结果，向后台发送数据
	var txt_and_pwd = content.getInputElementValue(content.txt_and_pwd_element);
	if (txt_and_pwd != null) {
		chrome.runtime.sendMessage({
			mode: mode.data,
			input: txt_and_pwd
		}, function(response) {
			console.log(response);
			for(var i = 0; i<response.length; i++) {
				//alert(response[i]);
				content.txt_and_pwd_element[i].value = response[i];
			}
		});
	} else {
		alert("该页面内没有找到合适的要加密的内容");
	}
	
	//关闭mask层
	$("#mask").remove();
	$("#pop-div").animate({
		left: 0,
		top: 0,
		opacity: "hide"
	}, "slow");
}


//接受来自pupup的以字符串形式传递的指令
chrome.runtime.onMessage.addListener(
	function(request, sender, sendResponse) {
		console.log("content收到消息");
		var func = content[request.instruction];
		func.apply(content,[request.mode]);
		
		/*
		sendResponse({
			
		});
		*/
	}
);




