// if (window.console) {
//   Function.prototype.makeMulti = function () {
//     let l = new String(this);
//     l = l.substring(l.indexOf("/*") + 3, l.lastIndexOf("*/"));
//     return l;
//   };
//   let string = function () {
//     /*

// ███╗   ███╗██╗   ██╗ ██████╗██████╗ ███████╗███╗   ██╗
// ████╗ ████║╚██╗ ██╔╝██╔════╝██╔══██╗██╔════╝████╗  ██║
// ██╔████╔██║ ╚████╔╝ ██║     ██████╔╝█████╗  ██╔██╗ ██║
// ██║╚██╔╝██║  ╚██╔╝  ██║     ██╔═══╝ ██╔══╝  ██║╚██╗██║
// ██║ ╚═╝ ██║   ██║   ╚██████╗██║     ███████╗██║ ╚████║
// ╚═╝     ╚═╝   ╚═╝    ╚═════╝╚═╝     ╚══════╝╚═╝  ╚═══╝

// */
//   };
//   // console.log(string.makeMulti());
//   console.log("\n欢迎访问 %cMycpenの学习笔记\n\n███╗   ███╗██╗   ██╗ ██████╗██████╗ ███████╗███╗   ██╗\n████╗ ████║╚██╗ ██╔╝██╔════╝██╔══██╗██╔════╝████╗  ██║\n██╔████╔██║ ╚████╔╝ ██║     ██████╔╝█████╗  ██╔██╗ ██║\n██║╚██╔╝██║  ╚██╔╝  ██║     ██╔═══╝ ██╔══╝  ██║╚██╗██║\n██║ ╚═╝ ██║   ██║   ╚██████╗██║     ███████╗██║ ╚████║\n╚═╝     ╚═╝   ╚═╝    ╚═════╝╚═╝     ╚══════╝╚═╝  ╚═══╝\n", "color:#5ca1ff;font-weight:bold");
// }



// 已写入主题配置 main.js
// "use strict";
// var now1 = new Date,
// 	HoldLog = console.log;
// console.log = function() {}, queueMicrotask(function() {
// 	console.log = function() {};

// 	function o() {
// 		HoldLog.apply(console, arguments)
// 	}
// 	var c = new Date("08/28/2022 00:00:00");
// 	var d = new Date("10/22/1998 00:00:00");
// 	var e = new Date("10/22/2058 00:00:00");
// 	now1.setTime(now1.getTime() + 250);
// 	var c = ["欢迎访问 ", "cpen.top", "\n\n███╗   ███╗██╗   ██╗ ██████╗██████╗ ███████╗███╗   ██╗\n████╗ ████║╚██╗ ██╔╝██╔════╝██╔══██╗██╔════╝████╗  ██║\n██╔████╔██║ ╚████╔╝ ██║     ██████╔╝█████╗  ██╔██╗ ██║\n██║╚██╔╝██║  ╚██╔╝  ██║     ██╔═══╝ ██╔══╝  ██║╚██╗██║\n██║ ╚═╝ ██║   ██║   ╚██████╗██║     ███████╗██║ ╚████║\n╚═╝     ╚═╝   ╚═╝    ╚═════╝╚═╝     ╚══════╝╚═╝  ╚═══╝\n", "距 2022-08-28 已上线", Math.floor((now1 - c) / 1e3 / 60 / 60 / 24), "天", "距 1998-**-** 已过去", Math.floor((now1 - d) / 1e3 / 60 / 60 / 24), "天", "距 2058-**-** 倒计时", Math.floor(((e - now1) / 1e3 / 60 / 60 / 24) + 1), "天"],
// 		n = ["", "", "", ""];
// 	setTimeout(o.bind(console, "\n%c".concat(c[0], "%c").concat(c[1], "%c").concat(c[2], "%c").concat(c[3], "%c ").concat(c[4], "%c ").concat(c[5], "\n").concat(c[6], "%c ").concat(c[7], "%c ").concat(c[8], "\n").concat(c[9], "%c ").concat(c[10], "%c ").concat(c[11], "\n"), "", "color:#5ca1ff", "color:#5ca1ff", "color:#5ca1ff", "", "color:#5ca1ff", "", "color:#5ca1ff", "", "color:#5ca1ff"))
// });




