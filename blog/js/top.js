//js有一个小问题：就是只要鼠标滚动不论哪里都会响应，即便你滚动的是子元素
window.onscroll = percent; // 执行函数
// 页面百分比
function percent() {

  // document.getElementById("page-name").innerText = document.title.split(" | 陈鹏的个人主页")[0];
  document.getElementById("page-name").innerText = document.title.split(" | Mycpen")[0];
}




