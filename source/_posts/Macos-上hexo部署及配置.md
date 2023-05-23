---
title: Macos 上hexo部署及配置
date: 2017-10-22 07:28:02
tags: 
    - blog
---

# Macos 上hexo部署及配置

## 0x00

之前是在阿里云上用WordPress搭的一个服务器。由于服务器快到期了，再加上Wordpress一直有爆漏洞,就决定使用静态页面挂在GitHub上搭博客了。使用的是Hexo，比较方便，而且主题也挺好看。用篇文章记录一下，顺便练习一下Markdown。

## 0x01 环境准备

### GitHub账号

注册即可，无需翻墙。

### Node.js

[Node.js](http://nodejs.cn/download/ "Node.js") 官网下载安装即可。

### Git

安装Xcode时，会自带Git，如果没有就安装下Xcode或者Xcode的工具。

### hexo

首先创建一个放置博客系统的文件夹，这个文件夹就是你的博客的根目录，进入到文件夹，执行如下命令安装：

`sudo npm install -g hexo`

接着初始化：

`hexo init`

还需要安装一个上传博客到GitHub的工具：

`npm install hexo-deployer-git --save`

## 0x02 GitHub配置

### 仓库创建

建立与你的GitHub账户名对应的仓库，仓库名为`Your_name.github.io`。

接着配置你的hexo与该账号关联，在当前目录中的\_config.yml中：

![](/img/hexoblog/1.png)

`type`: `git`

`repo`： `https://github.com/Your_name/Your_name.github.io.git`

`branch`: `master`

特别要注意的是yml文件中的每个冒号后面需要一个空格。

然后在命令行中，配置你的GitHub信息：

`git config --global user.name "Yourname"`

`git config --global user.email "YourEmail"`

然后在命令行中，创建SSH key:

`ssh-keygen -t rsa -C "YourEmail"`

然后:

`cd ~/.ssh`

`cat id_rsa.pub`

然后将这个文件的内容复制下来。进入到你的GitHub账号->Settings->SSH and GPG keys，点击`NewSSH Key`，`title`随便填，`key`填你刚才复制的东西。然后保存即可。

## 0x03 博客配置

### 基本操作

-   hexo clean 清除静态文件(有些主题)
    \*   hexo generate 编译静态文件
    \*   hexo deploy 上传到你的GitHub
    \*   hexo server 在本地部署，在浏览器中输入localhost:4000即可预览
    \*   hexo new “文章名” 创建一篇文章，会在博客根目录下的source/\_post/下生成一个`文章名.md`的文件，在这个md里编辑文章即可。

一般上传就使用hexo g && hexo d 即可

### 基本配置

都是在 \_config.yml里配置：

-   `title`: `你的博客名字`
-   `language`: `zh-CN`
-   `theme`: `你要使用的主题，在根目录下的themes里`

### 主题更换

hexo有很多好看的主题，[知乎–有哪些好看的hexo主题](https://www.zhihu.com/question/24422335 "知乎–有哪些好看的hexo主题")

选个喜欢的主题，它的GitHub上会有部署的教程。

基本步骤是，在博客的根目录下的themes目录下，创建你要使用的主题的文件夹，进入文件夹，然后git clone 主题的仓库地址。跟主题相关的配置一般都在该主题的文件夹下的\_config.yml里。

别忘了在\_config.yml里更改`theme`的值

## 0x04 域名绑定

现在要想访问你的blog的地址是 Your\_name.github.io,你可以绑定到你注册过的域名。

先改一下DNS解析，我是在阿里云买的,直接在阿里云的控制台里,更改我的域名的解析,记录类型是CNAME，就是一个跳转，主机记录是设置你的二级域名，记录值填你原来的博客地址。

![](/img/hexoblog/2.png)

然后在你博客的根目录的`Source`文件夹下，创建一个`CNAME`文件，在文件里写下你购买的域名。

如我是`https://blog.yoyolllh.top`

然后再 `hexo g && hexo d` 重新上传一下就可以通过你的域名访问了。

## 0x05 总结

踩了许多的坑，小小总结一下

-   在更换主题时，严格按照主题的README操作。
-   绑定域名记得一定要创建`CNAME`文件，光在GitHub上绑定域名没有用，每次你重新上传时它都会解除绑定。
-   使用 `hexo g --config source/_data/next.yml`重新指定配置文件生成静态文件。
-   有些主题配置后仍使用不了，可以试试 `hexo clean`命令。

