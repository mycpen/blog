!function(i,e){"use strict";function o(i){for(var e={},o=0;o<i.length;o++)e[i[o].toUpperCase()]=i[o];return e}function a(i,e){return typeof i===u&&-1!==$(e).indexOf($(i))}function r(i,e){if(typeof i===u)return i=i.replace(/^\s\s*/,w),typeof e==l?i:i.substring(0,350)}function t(i,o){for(var a,r,t,n,s,b=0;b<o.length&&!n;){for(var w=o[b],l=o[b+1],u=a=0;u<w.length&&!n&&w[u];)if(n=w[u++].exec(i))for(r=0;r<l.length;r++)s=n[++a],typeof(t=l[r])===c&&0<t.length?2===t.length?typeof t[1]==d?this[t[0]]=t[1].call(this,s):this[t[0]]=t[1]:3===t.length?typeof t[1]!==d||t[1].exec&&t[1].test?this[t[0]]=s?s.replace(t[1],t[2]):e:this[t[0]]=s?t[1].call(this,s,t[2]):e:4===t.length&&(this[t[0]]=s?t[3].call(this,s.replace(t[1],t[2])):e):this[t]=s||e;b+=2}}function n(i,o){for(var r in o)if(typeof o[r]===c&&0<o[r].length){for(var t=0;t<o[r].length;t++)if(a(o[r][t],i))return"?"===r?e:r}else if(a(o[r],i))return"?"===r?e:r;return i}function s(o,a){if(typeof o===c&&(a=o,o=e),!(this instanceof s))return new s(o,a).getResult();var n=typeof i!=l&&i.navigator?i.navigator:e,b=o||(n&&n.userAgent?n.userAgent:w),k=n&&n.userAgentData?n.userAgentData:e,T=a?function(i,e){var o,a={};for(o in i)e[o]&&e[o].length%2==0?a[o]=e[o].concat(i[o]):a[o]=i[o];return a}(K,a):K,S=n&&n.userAgent==b;return this.getBrowser=function(){var i,o={};return o[h]=e,o[v]=e,t.call(o,b,T.browser),o[p]=typeof(i=o[v])===u?i.replace(/[^\d\.]/g,w).split(".")[0]:e,S&&n&&n.brave&&typeof n.brave.isBrave==d&&(o[h]="Brave"),o},this.getCPU=function(){var i={};return i[x]=e,t.call(i,b,T.cpu),i},this.getDevice=function(){var i={};return i[g]=e,i[m]=e,i[f]=e,t.call(i,b,T.device),S&&!i[f]&&k&&k.mobile&&(i[f]=y),S&&"Macintosh"==i[m]&&n&&typeof n.standalone!=l&&n.maxTouchPoints&&2<n.maxTouchPoints&&(i[m]="iPad",i[f]=_),i},this.getEngine=function(){var i={};return i[h]=e,i[v]=e,t.call(i,b,T.engine),i},this.getOS=function(){var i={};return i[h]=e,i[v]=e,t.call(i,b,T.os),S&&!i[h]&&k&&"Unknown"!=k.platform&&(i[h]=k.platform.replace(/chrome os/i,L).replace(/macos/i,Z)),i},this.getResult=function(){return{ua:this.getUA(),browser:this.getBrowser(),engine:this.getEngine(),os:this.getOS(),device:this.getDevice(),cpu:this.getCPU()}},this.getUA=function(){return b},this.setUA=function(i){return b=typeof i===u&&350<i.length?r(i,350):i,this},this.setUA(b),this}var b,w="",d="function",l="undefined",c="object",u="string",p="major",m="model",h="name",f="type",g="vendor",v="version",x="architecture",k="console",y="mobile",_="tablet",T="smarttv",S="wearable",q="embedded",z="Amazon",N="Apple",A="ASUS",C="BlackBerry",E="Browser",O="Chrome",U="Firefox",j="Google",P="Huawei",R="LG",M="Microsoft",B="Motorola",V="Opera",D="Samsung",I="Sharp",W="Sony",F="Xiaomi",G="Zebra",H="Facebook",L="Chromium OS",Z="Mac OS",$=function(i){return i.toLowerCase()},X={ME:"4.90","NT 3.11":"NT3.51","NT 4.0":"NT4.0",2e3:"NT 5.0",XP:["NT 5.1","NT 5.2"],Vista:"NT 6.0",7:"NT 6.1",8:"NT 6.2",8.1:"NT 6.3",10:["NT 6.4","NT 10.0"],RT:"ARM"},K={browser:[[/\b(?:crmo|crios)\/([\w\.]+)/i],[v,[h,"Chrome"]],[/edg(?:e|ios|a)?\/([\w\.]+)/i],[v,[h,"Edge"]],[/(opera mini)\/([-\w\.]+)/i,/(opera [mobiletab]{3,6})\b.+version\/([-\w\.]+)/i,/(opera)(?:.+version\/|[\/ ]+)([\w\.]+)/i],[h,v],[/opios[\/ ]+([\w\.]+)/i],[v,[h,V+" Mini"]],[/\bopr\/([\w\.]+)/i],[v,[h,V]],[/(kindle)\/([\w\.]+)/i,/(lunascape|maxthon|netfront|jasmine|blazer)[\/ ]?([\w\.]*)/i,/(avant |iemobile|slim)(?:browser)?[\/ ]?([\w\.]*)/i,/(ba?idubrowser)[\/ ]?([\w\.]+)/i,/(?:ms|\()(ie) ([\w\.]+)/i,/(flock|rockmelt|midori|epiphany|silk|skyfire|bolt|iron|vivaldi|iridium|phantomjs|bowser|quark|qupzilla|falkon|rekonq|puffin|brave|whale(?!.+naver)|qqbrowserlite|qq|duckduckgo)\/([-\w\.]+)/i,/(heytap|ovi)browser\/([\d\.]+)/i,/(weibo)__([\d\.]+)/i],[h,v],[/(?:\buc? ?browser|(?:juc.+)ucweb)[\/ ]?([\w\.]+)/i],[v,[h,"UC"+E]],[/microm.+\bqbcore\/([\w\.]+)/i,/\bqbcore\/([\w\.]+).+microm/i],[v,[h,"WeChat(Win) Desktop"]],[/micromessenger\/([\w\.]+)/i],[v,[h,"WeChat"]],[/konqueror\/([\w\.]+)/i],[v,[h,"Konqueror"]],[/trident.+rv[: ]([\w\.]{1,9})\b.+like gecko/i],[v,[h,"IE"]],[/ya(?:search)?browser\/([\w\.]+)/i],[v,[h,"Yandex"]],[/(avast|avg)\/([\w\.]+)/i],[[h,/(.+)/,"$1 Secure "+E],v],[/\bfocus\/([\w\.]+)/i],[v,[h,U+" Focus"]],[/\bopt\/([\w\.]+)/i],[v,[h,V+" Touch"]],[/coc_coc\w+\/([\w\.]+)/i],[v,[h,"Coc Coc"]],[/dolfin\/([\w\.]+)/i],[v,[h,"Dolphin"]],[/coast\/([\w\.]+)/i],[v,[h,V+" Coast"]],[/miuibrowser\/([\w\.]+)/i],[v,[h,"MIUI "+E]],[/fxios\/([-\w\.]+)/i],[v,[h,U]],[/\bqihu|(qi?ho?o?|360)browser/i],[[h,"360 "+E]],[/(oculus|samsung|sailfish|huawei)browser\/([\w\.]+)/i],[[h,/(.+)/,"$1 "+E],v],[/(comodo_dragon)\/([\w\.]+)/i],[[h,/_/g," "],v],[/(electron)\/([\w\.]+) safari/i,/(tesla)(?: qtcarbrowser|\/(20\d\d\.[-\w\.]+))/i,/m?(qqbrowser|baiduboxapp|2345Explorer)[\/ ]?([\w\.]+)/i],[h,v],[/(metasr)[\/ ]?([\w\.]+)/i,/(lbbrowser)/i,/\[(linkedin)app\]/i],[h],[/((?:fban\/fbios|fb_iab\/fb4a)(?!.+fbav)|;fbav\/([\w\.]+);)/i],[[h,H],v],[/(kakao(?:talk|story))[\/ ]([\w\.]+)/i,/(naver)\(.*?(\d+\.[\w\.]+).*\)/i,/safari (line)\/([\w\.]+)/i,/\b(line)\/([\w\.]+)\/iab/i,/(chromium|instagram)[\/ ]([-\w\.]+)/i],[h,v],[/\bgsa\/([\w\.]+) .*safari\//i],[v,[h,"GSA"]],[/musical_ly(?:.+app_?version\/|_)([\w\.]+)/i],[v,[h,"TikTok"]],[/headlesschrome(?:\/([\w\.]+)| )/i],[v,[h,O+" Headless"]],[/ wv\).+(chrome)\/([\w\.]+)/i],[[h,O+" WebView"],v],[/droid.+ version\/([\w\.]+)\b.+(?:mobile safari|safari)/i],[v,[h,"Android "+E]],[/(chrome|omniweb|arora|[tizenoka]{5} ?browser)\/v?([\w\.]+)/i],[h,v],[/version\/([\w\.\,]+) .*mobile\/\w+ (safari)/i],[v,[h,"Mobile Safari"]],[/version\/([\w(\.|\,)]+) .*(mobile ?safari|safari)/i],[v,h],[/webkit.+?(mobile ?safari|safari)(\/[\w\.]+)/i],[h,[v,n,{"1.0":"/8",1.2:"/1",1.3:"/3","2.0":"/412","2.0.2":"/416","2.0.3":"/417","2.0.4":"/419","?":"/"}]],[/(webkit|khtml)\/([\w\.]+)/i],[h,v],[/(navigator|netscape\d?)\/([-\w\.]+)/i],[[h,"Netscape"],v],[/mobile vr; rv:([\w\.]+)\).+firefox/i],[v,[h,U+" Reality"]],[/ekiohf.+(flow)\/([\w\.]+)/i,/(swiftfox)/i,/(icedragon|iceweasel|camino|chimera|fennec|maemo browser|minimo|conkeror|klar)[\/ ]?([\w\.\+]+)/i,/(seamonkey|k-meleon|icecat|iceape|firebird|phoenix|palemoon|basilisk|waterfox)\/([-\w\.]+)$/i,/(firefox)\/([\w\.]+)/i,/(mozilla)\/([\w\.]+) .+rv\:.+gecko\/\d+/i,/(polaris|lynx|dillo|icab|doris|amaya|w3m|netsurf|sleipnir|obigo|mosaic|(?:go|ice|up)[\. ]?browser)[-\/ ]?v?([\w\.]+)/i,/(links) \(([\w\.]+)/i,/panasonic;(viera)/i],[h,v],[/(cobalt)\/([\w\.]+)/i],[h,[v,/master.|lts./,""]]],cpu:[[/(?:(amd|x(?:(?:86|64)[-_])?|wow|win)64)[;\)]/i],[[x,"amd64"]],[/(ia32(?=;))/i],[[x,$]],[/((?:i[346]|x)86)[;\)]/i],[[x,"ia32"]],[/\b(aarch64|arm(v?8e?l?|_?64))\b/i],[[x,"arm64"]],[/\b(arm(?:v[67])?ht?n?[fl]p?)\b/i],[[x,"armhf"]],[/windows (ce|mobile); ppc;/i],[[x,"arm"]],[/((?:ppc|powerpc)(?:64)?)(?: mac|;|\))/i],[[x,/ower/,w,$]],[/(sun4\w)[;\)]/i],[[x,"sparc"]],[/((?:avr32|ia64(?=;))|68k(?=\))|\barm(?=v(?:[1-7]|[5-7]1)l?|;|eabi)|(?=atmel )avr|(?:irix|mips|sparc)(?:64)?\b|pa-risc)/i],[[x,$]]],device:[[/\b(sch-i[89]0\d|shw-m380s|sm-[ptx]\w{2,4}|gt-[pn]\d{2,4}|sgh-t8[56]9|nexus 10)/i],[m,[g,D],[f,_]],[/\b((?:s[cgp]h|gt|sm)-\w+|sc[g-]?[\d]+a?|galaxy nexus)/i,/samsung[- ]([-\w]+)/i,/sec-(sgh\w+)/i],[m,[g,D],[f,y]],[/(?:\/|\()(ip(?:hone|od)[\w, ]*)(?:\/|;)/i],[m,[g,N],[f,y]],[/\((ipad);[-\w\),; ]+apple/i,/applecoremedia\/[\w\.]+ \((ipad)/i,/\b(ipad)\d\d?,\d\d?[;\]].+ios/i],[m,[g,N],[f,_]],[/(macintosh);/i],[m,[g,N]],[/\b(sh-?[altvz]?\d\d[a-ekm]?)/i],[m,[g,I],[f,y]],[/\b((?:ag[rs][23]?|bah2?|sht?|btv)-a?[lw]\d{2})\b(?!.+d\/s)/i],[m,[g,P],[f,_]],[/(?:huawei|honor)([-\w ]+)[;\)]/i,/\b(nexus 6p|\w{2,4}e?-[atu]?[ln][\dx][012359c][adn]?)\b(?!.+d\/s)/i],[m,[g,P],[f,y]],[/\b(poco[\w ]+)(?: bui|\))/i,/\b; (\w+) build\/hm\1/i,/\b(hm[-_ ]?note?[_ ]?(?:\d\w)?) bui/i,/\b(redmi[\-_ ]?(?:note|k)?[\w_ ]+)(?: bui|\))/i,/\b(mi[-_ ]?(?:a\d|one|one[_ ]plus|note lte|max|cc)?[_ ]?(?:\d?\w?)[_ ]?(?:plus|se|lite)?)(?: bui|\))/i],[[m,/_/g," "],[g,F],[f,y]],[/\b(mi[-_ ]?(?:pad)(?:[\w_ ]+))(?: bui|\))/i],[[m,/_/g," "],[g,F],[f,_]],[/; (\w+) bui.+ oppo/i,/\b(cph[12]\d{3}|p(?:af|c[al]|d\w|e[ar])[mt]\d0|x9007|a101op)\b/i],[m,[g,"OPPO"],[f,y]],[/vivo (\w+)(?: bui|\))/i,/\b(v[12]\d{3}\w?[at])(?: bui|;)/i],[m,[g,"Vivo"],[f,y]],[/\b(rmx[12]\d{3})(?: bui|;|\))/i],[m,[g,"Realme"],[f,y]],[/\b(milestone|droid(?:[2-4x]| (?:bionic|x2|pro|razr))?:?( 4g)?)\b[\w ]+build\//i,/\bmot(?:orola)?[- ](\w*)/i,/((?:moto[\w\(\) ]+|xt\d{3,4}|nexus 6)(?= bui|\)))/i],[m,[g,B],[f,y]],[/\b(mz60\d|xoom[2 ]{0,2}) build\//i],[m,[g,B],[f,_]],[/((?=lg)?[vl]k\-?\d{3}) bui| 3\.[-\w; ]{10}lg?-([06cv9]{3,4})/i],[m,[g,R],[f,_]],[/(lm(?:-?f100[nv]?|-[\w\.]+)(?= bui|\))|nexus [45])/i,/\blg[-e;\/ ]+((?!browser|netcast|android tv)\w+)/i,/\blg-?([\d\w]+) bui/i],[m,[g,R],[f,y]],[/(ideatab[-\w ]+)/i,/lenovo ?(s[56]000[-\w]+|tab(?:[\w ]+)|yt[-\d\w]{6}|tb[-\d\w]{6})/i],[m,[g,"Lenovo"],[f,_]],[/(?:maemo|nokia).*(n900|lumia \d+)/i,/nokia[-_ ]?([-\w\.]*)/i],[[m,/_/g," "],[g,"Nokia"],[f,y]],[/(pixel c)\b/i],[m,[g,j],[f,_]],[/droid.+; (pixel[\daxl ]{0,6})(?: bui|\))/i],[m,[g,j],[f,y]],[/droid.+ (a?\d[0-2]{2}so|[c-g]\d{4}|so[-gl]\w+|xq-a\w[4-7][12])(?= bui|\).+chrome\/(?![1-6]{0,1}\d\.))/i],[m,[g,W],[f,y]],[/sony tablet [ps]/i,/\b(?:sony)?sgp\w+(?: bui|\))/i],[[m,"Xperia Tablet"],[g,W],[f,_]],[/ (kb2005|in20[12]5|be20[12][59])\b/i,/(?:one)?(?:plus)? (a\d0\d\d)(?: b|\))/i],[m,[g,"OnePlus"],[f,y]],[/(alexa)webm/i,/(kf[a-z]{2}wi|aeo[c-r]{2})( bui|\))/i,/(kf[a-z]+)( bui|\)).+silk\//i],[m,[g,z],[f,_]],[/((?:sd|kf)[0349hijorstuw]+)( bui|\)).+silk\//i],[[m,/(.+)/g,"Fire Phone $1"],[g,z],[f,y]],[/(playbook);[-\w\),; ]+(rim)/i],[m,g,[f,_]],[/\b((?:bb[a-f]|st[hv])100-\d)/i,/\(bb10; (\w+)/i],[m,[g,C],[f,y]],[/(?:\b|asus_)(transfo[prime ]{4,10} \w+|eeepc|slider \w+|nexus 7|padfone|p00[cj])/i],[m,[g,A],[f,_]],[/ (z[bes]6[027][012][km][ls]|zenfone \d\w?)\b/i],[m,[g,A],[f,y]],[/(nexus 9)/i],[m,[g,"HTC"],[f,_]],[/(htc)[-;_ ]{1,2}([\w ]+(?=\)| bui)|\w+)/i,/(zte)[- ]([\w ]+?)(?: bui|\/|\))/i,/(alcatel|geeksphone|nexian|panasonic(?!(?:;|\.))|sony(?!-bra))[-_ ]?([-\w]*)/i],[g,[m,/_/g," "],[f,y]],[/droid.+; ([ab][1-7]-?[0178a]\d\d?)/i],[m,[g,"Acer"],[f,_]],[/droid.+; (m[1-5] note) bui/i,/\bmz-([-\w]{2,})/i],[m,[g,"Meizu"],[f,y]],[/(blackberry|benq|palm(?=\-)|sonyericsson|acer|asus|dell|meizu|motorola|polytron)[-_ ]?([-\w]*)/i,/(hp) ([\w ]+\w)/i,/(asus)-?(\w+)/i,/(microsoft); (lumia[\w ]+)/i,/(lenovo)[-_ ]?([-\w]+)/i,/(jolla)/i,/(oppo) ?([\w ]+) bui/i],[g,m,[f,y]],[/(kobo)\s(ereader|touch)/i,/(archos) (gamepad2?)/i,/(hp).+(touchpad(?!.+tablet)|tablet)/i,/(kindle)\/([\w\.]+)/i,/(nook)[\w ]+build\/(\w+)/i,/(dell) (strea[kpr\d ]*[\dko])/i,/(le[- ]+pan)[- ]+(\w{1,9}) bui/i,/(trinity)[- ]*(t\d{3}) bui/i,/(gigaset)[- ]+(q\w{1,9}) bui/i,/(vodafone) ([\w ]+)(?:\)| bui)/i],[g,m,[f,_]],[/(surface duo)/i],[m,[g,M],[f,_]],[/droid [\d\.]+; (fp\du?)(?: b|\))/i],[m,[g,"Fairphone"],[f,y]],[/(u304aa)/i],[m,[g,"AT&T"],[f,y]],[/\bsie-(\w*)/i],[m,[g,"Siemens"],[f,y]],[/\b(rct\w+) b/i],[m,[g,"RCA"],[f,_]],[/\b(venue[\d ]{2,7}) b/i],[m,[g,"Dell"],[f,_]],[/\b(q(?:mv|ta)\w+) b/i],[m,[g,"Verizon"],[f,_]],[/\b(?:barnes[& ]+noble |bn[rt])([\w\+ ]*) b/i],[m,[g,"Barnes & Noble"],[f,_]],[/\b(tm\d{3}\w+) b/i],[m,[g,"NuVision"],[f,_]],[/\b(k88) b/i],[m,[g,"ZTE"],[f,_]],[/\b(nx\d{3}j) b/i],[m,[g,"ZTE"],[f,y]],[/\b(gen\d{3}) b.+49h/i],[m,[g,"Swiss"],[f,y]],[/\b(zur\d{3}) b/i],[m,[g,"Swiss"],[f,_]],[/\b((zeki)?tb.*\b) b/i],[m,[g,"Zeki"],[f,_]],[/\b([yr]\d{2}) b/i,/\b(dragon[- ]+touch |dt)(\w{5}) b/i],[[g,"Dragon Touch"],m,[f,_]],[/\b(ns-?\w{0,9}) b/i],[m,[g,"Insignia"],[f,_]],[/\b((nxa|next)-?\w{0,9}) b/i],[m,[g,"NextBook"],[f,_]],[/\b(xtreme\_)?(v(1[045]|2[015]|[3469]0|7[05])) b/i],[[g,"Voice"],m,[f,y]],[/\b(lvtel\-)?(v1[12]) b/i],[[g,"LvTel"],m,[f,y]],[/\b(ph-1) /i],[m,[g,"Essential"],[f,y]],[/\b(v(100md|700na|7011|917g).*\b) b/i],[m,[g,"Envizen"],[f,_]],[/\b(trio[-\w\. ]+) b/i],[m,[g,"MachSpeed"],[f,_]],[/\btu_(1491) b/i],[m,[g,"Rotor"],[f,_]],[/(shield[\w ]+) b/i],[m,[g,"Nvidia"],[f,_]],[/(sprint) (\w+)/i],[g,m,[f,y]],[/(kin\.[onetw]{3})/i],[[m,/\./g," "],[g,M],[f,y]],[/droid.+; (cc6666?|et5[16]|mc[239][23]x?|vc8[03]x?)\)/i],[m,[g,G],[f,_]],[/droid.+; (ec30|ps20|tc[2-8]\d[kx])\)/i],[m,[g,G],[f,y]],[/smart-tv.+(samsung)/i],[g,[f,T]],[/hbbtv.+maple;(\d+)/i],[[m,/^/,"SmartTV"],[g,D],[f,T]],[/(nux; netcast.+smarttv|lg (netcast\.tv-201\d|android tv))/i],[[g,R],[f,T]],[/(apple) ?tv/i],[g,[m,N+" TV"],[f,T]],[/crkey/i],[[m,O+"cast"],[g,j],[f,T]],[/droid.+aft(\w)( bui|\))/i],[m,[g,z],[f,T]],[/\(dtv[\);].+(aquos)/i,/(aquos-tv[\w ]+)\)/i],[m,[g,I],[f,T]],[/(bravia[\w ]+)( bui|\))/i],[m,[g,W],[f,T]],[/(mitv-\w{5}) bui/i],[m,[g,F],[f,T]],[/Hbbtv.*(technisat) (.*);/i],[g,m,[f,T]],[/\b(roku)[\dx]*[\)\/]((?:dvp-)?[\d\.]*)/i,/hbbtv\/\d+\.\d+\.\d+ +\([\w\+ ]*; *([\w\d][^;]*);([^;]*)/i],[[g,r],[m,r],[f,T]],[/\b(android tv|smart[- ]?tv|opera tv|tv; rv:)\b/i],[[f,T]],[/(ouya)/i,/(nintendo) ([wids3utch]+)/i],[g,m,[f,k]],[/droid.+; (shield) bui/i],[m,[g,"Nvidia"],[f,k]],[/(playstation [345portablevi]+)/i],[m,[g,W],[f,k]],[/\b(xbox(?: one)?(?!; xbox))[\); ]/i],[m,[g,M],[f,k]],[/((pebble))app/i],[g,m,[f,S]],[/(watch)(?: ?os[,\/]|\d,\d\/)[\d\.]+/i],[m,[g,N],[f,S]],[/droid.+; (glass) \d/i],[m,[g,j],[f,S]],[/droid.+; (wt63?0{2,3})\)/i],[m,[g,G],[f,S]],[/(quest( 2| pro)?)/i],[m,[g,H],[f,S]],[/(tesla)(?: qtcarbrowser|\/[-\w\.]+)/i],[g,[f,q]],[/(aeobc)\b/i],[m,[g,z],[f,q]],[/droid .+?; ([^;]+?)(?: bui|\) applew).+? mobile safari/i],[m,[f,y]],[/droid .+?; ([^;]+?)(?: bui|\) applew).+?(?! mobile) safari/i],[m,[f,_]],[/\b((tablet|tab)[;\/]|focus\/\d(?!.+mobile))/i],[[f,_]],[/(phone|mobile(?:[;\/]| [ \w\/\.]*safari)|pda(?=.+windows ce))/i],[[f,y]],[/(android[-\w\. ]{0,9});.+buil/i],[m,[g,"Generic"]]],engine:[[/windows.+ edge\/([\w\.]+)/i],[v,[h,"EdgeHTML"]],[/webkit\/537\.36.+chrome\/(?!27)([\w\.]+)/i],[v,[h,"Blink"]],[/(presto)\/([\w\.]+)/i,/(webkit|trident|netfront|netsurf|amaya|lynx|w3m|goanna)\/([\w\.]+)/i,/ekioh(flow)\/([\w\.]+)/i,/(khtml|tasman|links)[\/ ]\(?([\w\.]+)/i,/(icab)[\/ ]([23]\.[\d\.]+)/i,/\b(libweb)/i],[h,v],[/rv\:([\w\.]{1,9})\b.+(gecko)/i],[v,h]],os:[[/microsoft (windows) (vista|xp)/i],[h,v],[/(windows) nt 6\.2; (arm)/i,/(windows (?:phone(?: os)?|mobile))[\/ ]?([\d\.\w ]*)/i,/(windows)[\/ ]?([ntce\d\. ]+\w)(?!.+xbox)/i],[h,[v,n,X]],[/(win(?=3|9|n)|win 9x )([nt\d\.]+)/i],[[h,"Windows"],[v,n,X]],[/ip[honead]{2,4}\b(?:.*os ([\w]+) like mac|; opera)/i,/ios;fbsv\/([\d\.]+)/i,/cfnetwork\/.+darwin/i],[[v,/_/g,"."],[h,"iOS"]],[/(mac os x) ?([\w\. ]*)/i,/(macintosh|mac_powerpc\b)(?!.+haiku)/i],[[h,Z],[v,/_/g,"."]],[/droid ([\w\.]+)\b.+(android[- ]x86|harmonyos)/i],[v,h],[/(android|webos|qnx|bada|rim tablet os|maemo|meego|sailfish)[-\/ ]?([\w\.]*)/i,/(blackberry)\w*\/([\w\.]*)/i,/(tizen|kaios)[\/ ]([\w\.]+)/i,/\((series40);/i],[h,v],[/\(bb(10);/i],[v,[h,C]],[/(?:symbian ?os|symbos|s60(?=;)|series60)[-\/ ]?([\w\.]*)/i],[v,[h,"Symbian"]],[/mozilla\/[\d\.]+ \((?:mobile|tablet|tv|mobile; [\w ]+); rv:.+ gecko\/([\w\.]+)/i],[v,[h,U+" OS"]],[/web0s;.+rt(tv)/i,/\b(?:hp)?wos(?:browser)?\/([\w\.]+)/i],[v,[h,"webOS"]],[/watch(?: ?os[,\/]|\d,\d\/)([\d\.]+)/i],[v,[h,"watchOS"]],[/crkey\/([\d\.]+)/i],[v,[h,O+"cast"]],[/(cros) [\w]+(?:\)| ([\w\.]+)\b)/i],[[h,L],v],[/panasonic;(viera)/i,/(netrange)mmh/i,/(nettv)\/(\d+\.[\w\.]+)/i,/(nintendo|playstation) ([wids345portablevuch]+)/i,/(xbox); +xbox ([^\);]+)/i,/\b(joli|palm)\b ?(?:os)?\/?([\w\.]*)/i,/(mint)[\/\(\) ]?(\w*)/i,/(mageia|vectorlinux)[; ]/i,/([kxln]?ubuntu|debian|suse|opensuse|gentoo|arch(?= linux)|slackware|fedora|mandriva|centos|pclinuxos|red ?hat|zenwalk|linpus|raspbian|plan 9|minix|risc os|contiki|deepin|manjaro|elementary os|sabayon|linspire)(?: gnu\/linux)?(?: enterprise)?(?:[- ]linux)?(?:-gnu)?[-\/ ]?(?!chrom|package)([-\w\.]*)/i,/(hurd|linux) ?([\w\.]*)/i,/(gnu) ?([\w\.]*)/i,/\b([-frentopcghs]{0,5}bsd|dragonfly)[\/ ]?(?!amd|[ix346]{1,2}86)([\w\.]*)/i,/(haiku) (\w+)/i],[h,v],[/(sunos) ?([\w\.\d]*)/i],[[h,"Solaris"],v],[/((?:open)?solaris)[-\/ ]?([\w\.]*)/i,/(aix) ((\d)(?=\.|\)| )[\w\.])*/i,/\b(beos|os\/2|amigaos|morphos|openvms|fuchsia|hp-ux|serenityos)/i,/(unix) ?([\w\.]*)/i],[h,v]]},Q=(s.VERSION="1.0.35",s.BROWSER=o([h,v,p]),s.CPU=o([x]),s.DEVICE=o([m,g,f,k,y,T,_,S,q]),s.ENGINE=s.OS=o([h,v]),typeof exports!=l?(exports=typeof module!=l&&module.exports?module.exports=s:exports).UAParser=s:typeof define===d&&define.amd?define((function(){return s})):typeof i!=l&&(i.UAParser=s),typeof i!=l&&(i.jQuery||i.Zepto));Q&&!Q.ua&&(b=new s,Q.ua=b.getResult(),Q.ua.get=function(){return b.getUA()},Q.ua.set=function(i){b.setUA(i);var e,o=b.getResult();for(e in o)Q.ua[e]=o[e]})}("object"==typeof window?window:this);