// //标签条
// function tagsBarActive(){
//   var urlinfo = window.location.pathname;
//   urlinfo = decodeURIComponent(urlinfo)
//   //console.log(urlinfo);
//   //判断是否是首页
//   if (urlinfo == '/'){
//     if (document.querySelector('#tags-bar')){
//       document.getElementById('首页').classList.add("select")
//     }
//   }else {
//     // 验证是否是分类链接
//     var pattern = /\/tags\/.*?\//;
//     var patbool = pattern.test(urlinfo);
//     //console.log(patbool);
//     // 获取当前的标签
//     if (patbool) {
//       var valuegroup = urlinfo.split("/");
//       //console.log(valuegroup[2]);
//       // 获取当前分类
//       var nowTag = valuegroup[2];
//       if (document.querySelector('#category-bar')){
//         document.getElementById(nowTag).classList.add("select");
//       }
//     }
//   } 
// }
// tagsBarActive()

