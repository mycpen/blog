// fetch('https://v6-widget.51.la/v6/Jp8wwGQpp21utaFQ/quote.js').then(res => res.text()).then((data) => {
//     let title = ['最近活跃', '今日人数', '今日访问', '昨日人数', '昨日访问', '本月访问', '总访问量']
//     // let num = data.match(/(?<=<\/span><span>).*?(?=<\/span><\/p>)/g)
//     let num = data.match(/(<\/span><span>).*?(\/span><\/p>)/g)

//     num = num.map((el) => {
//       let val = el.replace(/(<\/span><span>)/g, '')
//       let str = val.replace(/(<\/span><\/p>)/g, '')
//       return str
//     })

//     let s = document.getElementById('statistic')
//     if (!CountUpOptions) {
//      var CountUpOptions = {
//         useEasing: true,  // 过渡动画效果，默认ture
//         useGrouping: true,  // 千分位效果，例：1000->1,000。默认true
//         separator: ',',   // 使用千分位时分割符号
//         decimal: '.',   // 小数位分割符号
//         prefix: '',    // 前置符号
//         suffix: ''    // 后置符号，可汉字
//       }
//     }

//     // 自定义不显示哪个或者显示哪个，如下为不显示 最近活跃访客 和 总访问量
//     let statistic = []
//     for (let i = 0; i < num.length; i++) {
//         if (i == 0 || i == num.length - 1) continue;
//         s.innerHTML += '<div><span>' + title[i] + '</span><span id='+ title[i] + '>' + num[i] + '</span></div>'
//         queueMicrotask(()=> {
//           statistic.push(new CountUp(title[i], 0, num[i], 0, 2, CountUpOptions))
//         })
//     }
    
//     setTimeout(()=> {
//       const throttleStatisticUP = btf.throttle(statisticUP, 200)
//       function statisticUP () {
//         let statisticElment = document.querySelector('.about-statistic.author-content-item');
//         if(isInViewPortOfOne(statisticElment)) {
//           for (let i = 0; i < num.length; i++) {
//             if (i == 0 || i == num.length - 1) continue;
//             statistic[i-1].start();
//           }
//           document.removeEventListener('scroll', throttleStatisticUP);
//         }
//       }
//       document.addEventListener('scroll', throttleStatisticUP)
//     })
    
// });
