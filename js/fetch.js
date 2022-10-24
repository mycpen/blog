//===========================================================
// 排序算法
function quickSort(arr, keyword){
  // keyword传入值'time'（按发布时间排序）或'updated'（按更新时间排序）
  if(arr.length == 0){return [];}
  var left = [];
  var right = [];
  var selectItem = arr[0];
  for(var i = 1; i < arr.length; i++){
    if(arr[i][keyword] > selectItem[keyword]){
      left.push(arr[i]);
    }
    else{
      right.push(arr[i]);
    }
  }
  return quickSort(left, keyword).concat(selectItem, quickSort(right, keyword));
}
// ======================================================
// 从本地内存读取配置信息
var fdatalist = JSON.parse(localStorage.getItem("fdatalist"));
// 抓取友链api信息并进行分割处理。存入本地存储
if (fdatalist){
  fetch(fdatalist.apiurl)
    .then(res => res.json())
    .then(json =>{
      // 获取友链朋友圈基本信息
      var statistical_data = json.statistical_data;
      //存入本地存储
      localStorage.setItem("statisticalList",JSON.stringify(statistical_data))
      // console.log(statistical_data);
      // 获取友链朋友圈文章列表
      var article_data = eval(json.article_data);
      // console.log(article_data);
      // 按创建时间排序
      var article_sortcreated = quickSort(article_data,'time');
      //存入本地存储
      localStorage.setItem("createdList",JSON.stringify(article_sortcreated))
      // 按更新时间排序
      var article_sortupdated = quickSort(article_data,'updated');
      //存入本地存储
      localStorage.setItem("updatedList",JSON.stringify(article_sortupdated))
      // console.log(article_sortcreated);
      // console.log(article_sortupdated);
    }
  )
}
