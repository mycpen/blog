function whenDOMReadyTitle() {

  if (document.title == 'Mycpen - 陈鹏的个人主页') {
    document.getElementById("page-name").innerText = 'Mycpen'
  } else {
    document.getElementById("page-name").innerText = document.title.split(" | Mycpen")[0];
  }


}

whenDOMReadyTitle() //打开网站之后先执行一次函数
document.addEventListener("pjax:complete", whenDOMReadyTitle) //pjax加载完成之后执行上面函数




//js有一个小问题：就是只要鼠标滚动不论哪里都会响应，即便你滚动的是子元素
window.onscroll = percent; // 执行函数
// 页面百分比
function percent() {



  // // 即可短文
  // if (document.querySelector('#bber-talk')) {
  //   var swiper = new Swiper('.swiper-container', {
  //     direction: 'vertical', // 垂直切换选项
  //     loop: true,
  //     autoplay: {
  //     delay: 3000,
  //     pauseOnMouseEnter: true
  //   },
  //   });
  // }

  // if (document.title == 'Mycpen - 陈鹏的个人主页') {
  //   document.getElementById("page-name").innerText = 'Mycpen'
  // } else {
  //   document.getElementById("page-name").innerText = document.title.split(" | Mycpen")[0];
  // }

  // document.getElementById("page-name").innerText = document.title.split(" | 陈鹏的个人主页")[0];


  let a = document.documentElement.scrollTop || window.pageYOffset, // 卷去高度
    b =
      Math.max(
        document.body.scrollHeight,
        document.documentElement.scrollHeight,
        document.body.offsetHeight,
        document.documentElement.offsetHeight,
        document.body.clientHeight,
        document.documentElement.clientHeight
      ) - document.documentElement.clientHeight, // 整个网页高度 减去 可视高度
    result = Math.round((a / b) * 100), // 计算百分比
    btn = document.querySelector('#percent'); // 获取图标

  result <= 99 || (result = 99), (btn.innerHTML = result);
  r = window.scrollY + document.documentElement.clientHeight;
  p = document.getElementById('post-comment') || document.getElementById('footer');

  p.offsetTop + p.offsetHeight / 2 < r || 90 < result
    ? (document.querySelector('#nav-totop').classList.add('long'), (btn.innerHTML = '返回顶部'))
    : (document.querySelector('#nav-totop').classList.remove('long'), (btn.innerHTML = result));
}


//2022.9.11 已修复，需要jq，请自行引入
document.getElementById("name-container").setAttribute("style", "display:none");

var position = $(window).scrollTop();

$(window).scroll(function () {

  var scroll = $(window).scrollTop();

  if (scroll > position) {


    document.getElementById("name-container").setAttribute("style", "");
    // document.getElementById("search-button").setAttribute("style", "display:none!important");
    document.getElementsByClassName("menus_items")[1].setAttribute("style", "display:none!important");

  } else {
    document.getElementById("search-button").setAttribute("style", "");
    document.getElementsByClassName("menus_items")[1].setAttribute("style", "");
    document.getElementById("name-container").setAttribute("style", "display:none");

  }

  position = scroll;

});
function scrollToTop(){
    document.getElementsByClassName("menus_items")[1].setAttribute("style","");
    document.getElementById("name-container").setAttribute("style","display:none");
    btf.scrollToDest(0, 500);
}
//修复没有弄右键菜单的童鞋无法回顶部的问题
// document.getElementById("page-name").innerText = document.title.split(" | 陈鹏的个人主页")[0];
// document.getElementById("page-name").innerText=document.title
/*这里是去掉你的网站全局名称的设置，如果你不需要去掉，你可以写成：
document.getElementById("page-name").innerText=document.title

或者把你的网站的分隔符和全局网站名称加上去*/




