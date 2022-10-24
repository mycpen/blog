
// ======================================================

// 打印友链基本信息
function loadStatistical(sdata){
// 友链页面的挂载容器
var container = document.getElementById('fcircleContainer');
// 基本信息的html结构

var messageBoard =`
<div id="fMessageBoard">
  <div class="fUpdatedTime">
    <span class="fLabel">最近更新时间：</span><span class="fMessage">${sdata.last_updated_time}</span>
  </div>
  <div class="fMessageItem">
    <div class="fActiveFriend fItem">
      <span class="fLabel">活跃友链数</span>
      <span class="fMeasureBar"><span class="fMeasure" style="width:${(sdata.active_num/sdata.friends_num * 100).toFixed(2)}%; background: rgba(89, 230, 54,0.6);">${(sdata.active_num/sdata.friends_num * 100).toFixed(2)}%</span></span>
      <span class="fMessage">${sdata.active_num}/${sdata.friends_num}</span>
    </div>
    <div class="fErrorSite fItem">
      <span class="fLabel">失联友链数</span>
      <span class="fMeasureBar"><span class="fMeasure" style="width:${(sdata.error_num/sdata.friends_num * 100).toFixed(2)}%; background: rgba(227, 23, 72, 0.6);">${(sdata.error_num/sdata.friends_num * 100).toFixed(2)}%</span></span>
      <span class="fMessage">${sdata.error_num}/${sdata.friends_num}</span>
    </div>
    <div class="fArticleNum fItem">
      <span class="fLabel">当前库存</span>
      <span class="fMeasureBar"><span class="fMeasure" style="width:${(sdata.article_num/Math.ceil(sdata.article_num / 100)).toFixed(2)}%; background: rgba(29, 217, 211, 0.6);">${(sdata.article_num/Math.ceil(sdata.article_num / 100)).toFixed(2)}%</span></span>
      <span class="fMessage">${sdata.article_num}/${Math.ceil(Number( sdata.article_num) / 100) * 100}</span>
    </div>
  </div>
  <div id="switchRankBtn">
    <span id="rankByCreated">created</span>
    <span>
    <input type="checkbox" id="switchRankMode" checked="true" onchange="checkRankMode()"/><label for="switchRankMode" id="switchRank">Toggle</label>
    </span>
    <span id="rankByUpdated">updated</span>
  </div>
</div>
`;
// 加载更多按钮
var loadMoreBtn = `
<div id="fcircleMoreBtn" onclick="loadMoreArticle()">
  <i class="fas fa-angle-double-down"></i>
</div>
`
// 原则上信息面板应该在最前面，所以用beforebegin表示从开始符前面插入
if(container){
  container.insertAdjacentHTML('beforebegin', messageBoard);
  // 为了不影响文章加载，选择afterend表示从结束符后面插入
  container.insertAdjacentHTML('afterend', loadMoreBtn);
  }
}

// ======================================================
// 打印友链内容
function loadArticleItem(datalist,start,end){
var fdatalist = JSON.parse(localStorage.getItem("fdatalist"));
// 声明友链页面的挂载容器
var container = document.getElementById('fcircleContainer');
// 循环读取输出友链信息
for (var i = start;i<end;i++){
var item = datalist[i];
var articleItem=`
  <div class="fArticleItem">
    <div class="fArticleAvatar">
      <a class="fArticlelink fAvatar" target="_blank" rel="noopener nofollow" href="${item.link}">
        <img src="${item.avatar}" alt="avatar"  onerror="this.src='${fdatalist.error_img}'; this.onerror = null;">
      </a>
      <div class="fArticleAuthor">
        ${item.author}
      </div>
    </div>
    <div class="fArticleMessage">
      <a class="fArticleTitle"  href="${item.link}" target="_blank" rel="noopener nofollow" data-title="${item.title}">
        ${item.title}
      </a>
      <div class="fArticleTime">
        <span class="fArticleCreated"><i class="far fa-calendar-alt">发表于</i>${item.created}</span>
        <span class="fArticleUpdated"><i class="fas fa-history">更新于</i>${item.updated}</span>
      </div>
    </div>
  </div>
`;
if(container){
// 为了便于和后续拼接，选择从容器尾部插入
container.insertAdjacentHTML('beforeend', articleItem);
    }
  }
}


// 初始化方法
function initFriendCircle(){
  // 获取友链挂载容器
  var fcircleContainer = document.getElementById('fcircleContainer')
  // 获取本地存储的友链基本信息
  var statistical_data = JSON.parse(localStorage.getItem("statisticalList"));
  // 从本地内存读取配置信息
  var fdatalist = JSON.parse(localStorage.getItem("fdatalist"));
  // 只有当容器、基本信息均存在时才执行初始化
  if (fcircleContainer && statistical_data && fdatalist){
    // 加载基本信息面板
    loadStatistical(statistical_data);
    // 获取切换排序按钮
    var switchRankMode = document.getElementById("switchRankMode");
    //根据当前选择的排序方案加载对应的排序内容
    if(switchRankMode.checked){
      // console.log("按更新时间排序");
      var article_sortupdated = JSON.parse(localStorage.getItem("updatedList"));
      loadArticleItem(article_sortupdated ,0,fdatalist.initnumber)
    }else{
      // console.log("按创建时间排序");
      var article_sortcreated = JSON.parse(localStorage.getItem("createdList"));
      loadArticleItem(article_sortcreated ,0,fdatalist.initnumber)
    }
  }
}

// 加载更多文章
function loadMoreArticle(){
  // 获取当前已加载的文章数
  var currentArticle = document.getElementsByClassName('fArticleItem').length;
  // 获取当前选择的排序方式
  var switchRankMode = document.getElementById("switchRankMode");
  // 从本地内存读取配置信息
  var fdatalist = JSON.parse(localStorage.getItem("fdatalist"));
  // 只有当两者均存在时才继续执行
  if (switchRankMode && fdatalist){
    if(switchRankMode.checked){
      // console.log("按更新时间排序");
      var article_sortupdated = JSON.parse(localStorage.getItem("updatedList"));
      // 从当前文章的下一篇开始，加载下一阶程篇数
      loadArticleItem(article_sortupdated,currentArticle,currentArticle + fdatalist.stepnumber)
    }else{
      // console.log("按创建时间排序");
      var article_sortcreated = JSON.parse(localStorage.getItem("createdList"));
      // 从当前文章的下一篇开始，加载下一阶程篇数
      loadArticleItem(article_sortcreated,currentArticle,currentArticle + fdatalist.stepnumber)
    }
  }
  // 向上滚动一篇文章的距离
  window.scrollBy(0,180)
}

//切换按钮
function checkRankMode(){
  // 首先清空现有的文章内容
  document.getElementById('fcircleContainer').innerHTML=''
  // 获取当前选择的排序方式
  var switchRankMode = document.getElementById("switchRankMode");
  // 从本地内存读取配置信息
  var fdatalist = JSON.parse(localStorage.getItem("fdatalist"));
  // 只有当两者均存在时才继续执行
  if (switchRankMode && fdatalist){
    //按更新时间排序
    if(switchRankMode.checked){
      // console.log("按更新时间排序");
      var article_sortupdated = JSON.parse(localStorage.getItem("updatedList"));
      //加载配置项中指定的初始化篇数
      loadArticleItem(article_sortupdated ,0,fdatalist.initnumber)
    }else{
      // console.log("按创建时间排序");
      var article_sortcreated = JSON.parse(localStorage.getItem("createdList"));
      //加载配置项中指定的初始化篇数
      loadArticleItem(article_sortcreated ,0,fdatalist.initnumber)
    }
  }
}
//执行初始化方法
initFriendCircle()
