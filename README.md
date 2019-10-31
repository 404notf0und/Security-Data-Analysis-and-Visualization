# Security-Data-Analysis-and-Visualization
## 2018-2020青年安全圈-活跃技术博主/博客
## 声明
* 所有数据均来自且仅来自公开信息，未加入个人先验知识，如有疑义，请及时联系root@4o4notfound.org。
* 公开这批数据是为了大家一起更快更好地学习，请不要滥用这批数据，由此引发的问题，本人将概不负责。

## Why
- **最初目的**：个人日常安全阅读资源不足，需要从博客、Github、Twitter等多个数据源补充。
- **延续目的**：以人为核心，系统化收集博客、Github、当前主要研究方向、所属安全组织、学校、公司、RSS、知乎、微博、Email等信息，缩小安全圈的范围。
  - **信息检索**：通过关键字检索，方便找人，缩小人与人之间的交流障碍。比如通过高校关键字，可以快速找到校友，通过网络ID快速找到博主。
  - **内容学习**：例如从主要研究方向入手，Follow不同方向活跃博主，补充阅读资源，紧追安全前沿。
  - **数据分析**：挖掘人与人之间的社交网络，判断自己当前所处位置，指引未来发展方向。
## What
1. **数据采集**

	此版本数据为采集到的公开数据，数据格式为：

    	Follow,Star,ID,Security_ID,Blog，Individual_Team_Company，Friend_Link_ID，Github，Weibo，Focus_On，Team，School_Company，Skills_Tags，Man_Tags，RSS，Twitter，Zhihu，Email，Contact，Famous_Projects
	对应的解释分别是：

		笔者在跟着学习的，笔者觉得不错推荐的，索引ID，网络ID，博客链接，个人(1)/团队(2)/公司(3)博客，友情链接的索引ID，Github地址，微博地址，主要研究领域，所属安全团队，所属高校/公司，技能标签（PHP？Python？Java），人物标签（摄影？动漫？文艺），RSS订阅地址，推特地址，知乎地址，邮箱地址，联系方式（QQ？微信？），著名开源项目

	采集到的Skillgs_Tags，Man_Tags，Zhihu三个字段数据很少且意义不大，故计划舍弃。
2. **数据缺失补全**

	通过挖掘人与人之间的社交关系，补全部分数据，此版本数据暂时不会公开。

## How&&Do
* **数据缺失补全**

## Result
* 输出一份价值较高的原始数据和分析结果，使用者以此可以达到信息检索、内容学习、纵观安全的目的。
* 输出一份Github与大安全资源。
## Github&&大安全

最近更新时间：2019/10/29

目录：
- [安全知识大综合](#安全知识大综合)
- [安全工具大综合](#安全工具大综合)
- [资产](#资产)
- [敏感信息泄露检测工具](#敏感信息泄露检测工具)
- [漏洞](#漏洞)
	- [漏洞知识综合](#漏洞知识综合)
	- [特定漏洞及利用](#特定漏洞及利用)
	- [漏洞通用工具](#漏洞通用工具)
- [渗透测试](#渗透测试)
	- [渗透测试知识](#渗透测试知识)
	- [渗透测试工具](#渗透测试工具)
- [红队](#红队)
- [各语言代码审计](#各语言代码审计)
- [Web安全](#Web安全)
	- [Web安全知识大综合](#Web安全知识大综合)
	- [Web安全工具](#Web安全工具)
- [移动安全](#移动安全)
- [IoT安全](#IoT安全)
- [二进制安全](#二进制安全)
- [系统安全](#系统安全)
- [智能安全](#智能安全)
- [域名相关工具](#域名相关工具)
- [密码相关工具](#密码相关工具)
- [CTF知识大综合](#CTF知识大综合)
- [数据分析](#数据分析)
- [其他安全工具](#其他安全工具)

## 安全知识大综合
- [sec-chart:安全思维导图集合](https://github.com/SecWiki/sec-chart)
- [Mind-Map:各种安全相关思维导图整理收集](https://github.com/phith0n/Mind-Map)
- [SecPaper:SecurityPaper For www.polaris-lab.com](https://github.com/PolarisLab/SecPaper)
- [sks:Security Knowledge Structure(安全知识汇总)](https://github.com/JoyChou93/sks)
- [MITRE | ATT&CK-CN ](https://github.com/klionsec/MITRE-ATT-CK-CN)
- [collection-document:Collection of quality safety articles](https://github.com/tom0li/collection-document)
- [GoogleHacking-Page](https://github.com/K0rz3n/GoogleHacking-Page)
- [security-conference-archive:Collection of Security Conference Slides/Papers](https://github.com/Xyntax/security-conference-archive)
- [Security-PPT:大安全各领域各公司各会议分享的PPT](https://github.com/FeeiCN/Security-PPT)
- [Newbie-Security-List:网络安全学习资料](https://github.com/findneo/Newbie-Security-List)

## 安全工具大综合
- [hack-for-tools:常用的黑客神器](https://github.com/backlion/hack-for-tools)
- [Scanners-Box:安全行业从业者自研开源扫描器合辑](https://github.com/We5ter/Scanners-Box)
- [Awesome Platforms](https://github.com/We5ter/Awesome-Platforms)

## 资产
- [w-digital-scanner/w12scan:网络资产发现引擎](https://github.com/w-digital-scanner/w12scan)

## 敏感信息泄露检测工具
- [GSIL:GitHub敏感信息泄露监控](https://github.com/FeeiCN/GSIL)
- [GitLeak:GitLeak 是一个从 Github 上查找密码信息的小工具](https://github.com/5alt/GitLeak)
- [GitHacker: A Git source leak exploit tool that restores the entire Git repository](https://github.com/WangYihang/GitHacker)
- [FileSensor:基于爬虫的动态敏感文件探测工具](https://github.com/Xyntax/FileSensor)
- [VKSRC/Github-Monitor:Github Sensitive Information Leakage Monitor(Github信息泄漏监控系统)](https://github.com/VKSRC/Github-Monitor)

## 漏洞
### 漏洞知识综合
- [wooyun_search:乌云公开漏洞、知识库搜索 search from wooyun.org](https://github.com/grt1st/wooyun_search)
- [1000php:1000个PHP代码审计案例(2016.7以前乌云公开漏洞)](https://github.com/Xyntax/1000php)
### 特定漏洞及利用
- [FastjsonExploit:fastjson漏洞快速利用框架](https://github.com/c0ny1/FastjsonExploit)
- [fastjson-remote-code-execute-poc](https://github.com/shengqi158/fastjson-remote-code-execute-poc)
- [upload-labs:一个想帮你总结所有类型的上传漏洞的靶场](https://github.com/c0ny1/upload-labs)
- [upload-fuzz-dic-builder:上传漏洞fuzz字典生成脚本](https://github.com/c0ny1/upload-fuzz-dic-builder)
- [xxe-lab:一个包含php,java,python,C#等各种语言版本的XXE漏洞Demo](https://github.com/c0ny1/xxe-lab)
- [redis-rce:Redis 4.x/5.x RCE](https://github.com/Ridter/redis-rce)
- [redis-rogue-server:Redis(<=5.0.5) RCE](https://github.com/n0b0dyCN/redis-rogue-server)
- [CVE-2017-11882](https://github.com/Ridter/CVE-2017-11882)
- [Exchange2domain:CVE-2018-8581](https://github.com/Ridter/Exchange2domain)
- [CVE-2014-7911_poc:Local root exploit for Nexus5 Android 4.4.4(KTU84P)](https://github.com/retme7/CVE-2014-7911_poc)
- [CVE-2019-2725命令回显](https://github.com/lufeirider/CVE-2019-2725)
### 漏洞通用工具
- [vulhub/vulhub:Pre-Built Vulnerable Environments Based on Docker-Compose](https://github.com/vulhub/vulhub)
- [vulhub/MetaDockers:Responsible for visualization the vulhub and docker](https://github.com/vulhub/MetaDockers)
- [windows-kernel-exploits:windows-kernel-exploits Windows平台提权漏洞集合](https://github.com/SecWiki/windows-kernel-exploits)
- [linux-kernel-exploits:linux-kernel-exploits Linux平台提权漏洞集合](https://github.com/SecWiki/linux-kernel-exploits)
- [java-sec-code:Java common vulnerabilities and security code](https://github.com/JoyChou93/java-sec-code)
- [SharpSploit:SharpSploit is a .NET post-exploitation library written in C#](https://github.com/cobbr/SharpSploit)
- [nse_vuln:Nmap扫描、漏洞利用脚本](https://github.com/Rvn0xsy/nse_vuln)
- [vulstudy:使用docker快速搭建各大漏洞学习平台，目前可以一键搭建12个平台](https://github.com/c0ny1/vulstudy)
- [Exploit-Framework:An Exploit framework for Web Vulnerabilities written in Python](https://github.com/WangYihang/Exploit-Framework)
- [chaitin/xray:xray 安全评估工具](https://github.com/chaitin/xray)

## 渗透测试
### 渗透测试知识
- [Mind-Map:超详细的渗透测试思维导图](https://github.com/iSafeBlue/Mind-Map)
- [pentest_study:从零开始内网渗透学习](https://github.com/l3m0n/pentest_study)
- [Intranet_Penetration_Tips:2018年初整理的一些内网渗透TIPS](https://github.com/Ridter/Intranet_Penetration_Tips)
- [Active-Directory-Pentest-Notes:个人域渗透学习笔记](https://github.com/uknowsec/Active-Directory-Pentest-Notes)
- [Pentest-and-Development-Tips:A collection of pentest and development tips](https://github.com/3gstudent/Pentest-and-Development-Tips)
- [Penetration_Testing_Case:用于记录分享一些有趣的案例](https://github.com/r35tart/Penetration_Testing_Case)
- [ew:内网穿透(跨平台)](https://github.com/idlefire/ew)
- [python-hacker-code:《python黑帽子：黑客与渗透测试编程之道》代码及实验文件，字典等](https://github.com/giantbranch/python-hacker-code)
- [The-Hacker-Playbook-3-Translation:译渗透测试实战第三版(红队版)](https://github.com/Snowming04/The-Hacker-Playbook-3-Translation)
### 渗透测试工具
- [WebPocket:Exploit management framework](https://github.com/TuuuNya/WebPocket)
- [pentest_tools:收集一些小型实用的工具](https://github.com/l3m0n/pentest_tools)
- [pentest:some pentest scripts & tools by yaseng@uauc.net](https://github.com/yaseng/pentest)
- [DiscoverTarget:前渗透信息探测工具集-URL采集](https://github.com/coco413/DiscoverTarget)
- [POC-T:渗透测试插件化并发框架](https://github.com/Xyntax/POC-T)
- [cmsPoc:CMS渗透测试框架](https://github.com/CHYbeta/cmsPoc)
- [Pentest:tools](https://github.com/Ridter/Pentest)
- [Berserker:针对Pentest或者CTF的一个fuzz payload项目](https://github.com/zer0yu/Berserker)
- [w-digital-scanner/w13scan:被动安全扫描器](https://github.com/w-digital-scanner/w13scan)
- [Pentest-tools:内网渗透工具](https://github.com/Brucetg/Pentest-tools)
- [TrackRay:溯光 (TrackRay) 3 beta⚡渗透测试框架（资产扫描|指纹识别|暴力破解|网页爬虫|端口扫描|漏洞扫描|代码审计|AWVS|NMAP|Metasploit|SQLMap）](https://github.com/iSafeBlue/TrackRay)
- [saucerframe:python3批量poc检测工具](https://github.com/saucer-man/saucerframe)

## 红队
- [Covenant:Covenant is a collaborative .NET C2 framework for red teamers](https://github.com/cobbr/Covenant)
- [RedTeamManual:红队作战手册](https://github.com/klionsec/RedTeamManual)

## 各语言代码审计
- [Audit-Learning:记录自己对《代码审计》的理解和总结](https://github.com/jiangsir404/Audit-Learning)
- [PHP-code-audit:代码审计，对一些大型cms漏洞的复现研究，更新源码和漏洞exp](https://github.com/jiangsir404/PHP-code-audit)
- [Code-Audit-Challenges](https://github.com/CHYbeta/Code-Audit-Challenges)
- [python_sec:python安全和代码审计相关资料收集](https://github.com/bit4woo/python_sec)
- [pyvulhunter:python audit tool 审计 注入 inject](https://github.com/shengqi158/pyvulhunter)
- [WhaleShark-Team/cobra:源代码安全审计工具](https://github.com/WhaleShark-Team/cobra)
- [Cobra-W:白盒源代码审计工具-白帽子版](https://github.com/LoRexxar/Cobra-W)


## Web安全知识大综合
- [Web-Security-Learning](https://github.com/CHYbeta/Web-Security-Learning)
- [WAF-Bypass:WAF Bypass Cheatsheet](https://github.com/CHYbeta/WAF-Bypass)
## Web安全工具
- [JSFinder:JSFinder is a tool for quickly extracting URLs and subdomains from JS files on a website.](https://github.com/Threezh1/JSFinder)
- [WebEye:一个快速简单地识别WEB服务器类型、CMS类型、WAF类型、WHOIS信息、以及语言框架的小脚本](https://github.com/zerokeeper/WebEye)
- [whatweb:更快速的进行Web应用指纹识别](https://github.com/l3m0n/whatweb)
- [WebFuzzAttack:web模糊测试 - 将漏洞可能性放大](https://github.com/l3m0n/WebFuzzAttack)
- [CMS-Hunter:CMS漏洞测试用例集合](https://github.com/SecWiki/CMS-Hunter)
- [w-digital-scanner/w9scan:Plug-in type web vulnerability scanner](https://github.com/w-digital-scanner/w9scan)
- [webshell:入侵分析时发现的Webshell后门](https://github.com/JoyChou93/webshell)
- [webshell-venom:免杀webshell无限生成工具(利用随机异或无限免杀D盾)](https://github.com/yzddmr6/webshell-venom)
- [as_webshell_venom:免杀webshell无限生成工具蚁剑版](https://github.com/yzddmr6/as_webshell_venom)
- [webshellSample:webshell sample for WebShell Log Analysis](https://github.com/tanjiti/webshellSample)
- [Javascript-Backdoor:Learn from Casey Smith @subTee](https://github.com/3gstudent/Javascript-Backdoor)
- [chunked-coding-converter:Burp suite 分块传输辅助插件](https://github.com/c0ny1/chunked-coding-converter)
- [Bypass_Disable_functions_Shell:一个各种方式突破Disable_functions达到命令执行的shell](https://github.com/l3m0n/Bypass_Disable_functions_Shell)
- [DirBrute:多线程WEB目录爆破工具](https://github.com/Xyntax/DirBrute)

## 移动安全
- [App_Security:App安全学习](https://github.com/Brucetg/App_Security)

## IoT安全
- [iot-security-wiki:IOT security wiki](https://github.com/yaseng/iot-security-wiki)

## 二进制安全
- [Some-Kernel-Fuzzing-Paper](https://github.com/k0keoyo/Some-Kernel-Fuzzing-Paper)
- [kDriver-Fuzzer:基于ioctlbf框架编写的驱动漏洞挖掘工具kDriver Fuzzer](https://github.com/k0keoyo/kDriver-Fuzzer)
- [awesome-vm-exploit:share some useful archives about vm and qemu escape exploit.](https://github.com/WinMin/awesome-vm-exploit)
- [ROPgadget:This tool lets you search your gadgets on your binaries to facilitate your ROP exploitation](https://github.com/JonathanSalwan/ROPgadget)
- [Triton:Triton is a Dynamic Binary Analysis (DBA) framework](https://github.com/JonathanSalwan/Triton)
- [PinTools:Pintool example and PoC for dynamic binary analysis](https://github.com/JonathanSalwan/PinTools)
- [binary-samples:Samples of binary with different formats and architectures](https://github.com/JonathanSalwan/binary-samples)
- [vm-escape:some interesting vm-escape game](https://github.com/ray-cp/vm-escape)
- [Binary-Reading-List:Things I know and will know about binaries.](https://github.com/firmianay/Binary-Reading-List)

## 系统安全
- [SuperDllHijack:一种通用Dll劫持技术，不再需要手工导出Dll的函数接口了](https://github.com/anhkgg/SuperDllHijack)
- [List-RDP-Connections-History:Use powershell to list the RDP Connections History of logged-in users or all users](https://github.com/3gstudent/List-RDP-Connections-History)
- [Eventlogedit-evtx--Evolution:Remove individual lines from Windows XML Event Log (EVTX) files](https://github.com/3gstudent/Eventlogedit-evtx--Evolution)
- [Software-Security-Learning](https://github.com/CHYbeta/Software-Security-Learning)

## 智能安全
- [AI-for-Security-Learning:安全场景、基于AI的安全算法和安全数据分析学习资料整理](https://github.com/404notf0und/AI-for-Security-Learning)
- [AI-Security-Learning:自身学习的安全数据科学和算法的学习资料](https://github.com/0xMJ/AI-Security-Learning)

## 域名相关安全工具
- [dnsAutoRebinding:ssrf、ssrfIntranetFuzz、dnsRebinding、recordEncode、dnsPoisoning、Support ipv4/ipv6](https://github.com/Tr3jer/dnsAutoRebinding)
- [domain_hunter:利用burp收集整个企业、组织的域名（不仅仅是单个主域名）的插件](https://github.com/bit4woo/domain_hunter)
- [GSDF:A domain searcher named GoogleSSLdomainFinder - 基于谷歌SSL透明证书的子域名查询工具](https://github.com/We5ter/GSDF)
- [ESD:枚举子域名](https://github.com/FeeiCN/ESD)

## 密码相关工具
- [sarkara:A experimental post-quantum cryptography library](https://github.com/quininer/sarkara)
- [genpAss:中国特色的弱口令生成器](https://github.com/RicterZ/genpAss)
- [passmaker:可以自定义规则的密码字典生成器,支持图形界面 A password-generator that base on the rules that you specified](https://github.com/bit4woo/passmaker)
- [WebCrack:网站后台弱口令/万能密码批量检测工具](https://github.com/yzddmr6/WebCrack)
- [Decryption-tool:内网密码搜集部分工具](https://github.com/klionsec/Decryption-tool)
- [RW_Password:此项目用来提取收集以往泄露的密码中符合条件的强弱密码](https://github.com/r35tart/RW_Password)


## CTF知识大综合
- [CTF-All-In-One:CTF竞赛入门指南](https://github.com/firmianay/CTF-All-In-One)
- [CTF_repo:收集我参加过的CTF的题集, 只有题目, 不含wp](https://github.com/Hcamael/CTF_repo)
- [CTF_web:a project aim to collect CTF web practices](https://github.com/wonderkun/CTF_web)
- [CTF-Challenge:CTF题目收集](https://github.com/meizjm3i/CTF-Challenge)
- [Writeups:国内各大CTF赛题及writeup整理](https://github.com/susers/Writeups)
- [awd_attack_framework:awd攻防常用脚本+不死马+crontab+防御方法](https://github.com/Wfzsec/awd_attack_framework)

## 数据分析
- [sec_profile:爬取secwiki和xuanwu.github.io/sec.today,分析安全信息站点、安全趋势、提取安全工作者账号](https://github.com/tanjiti/sec_profile)

## 其他安全工具
- [mooder:Mooder是一款开源、安全、简洁、强大的团队内部知识分享平台](https://github.com/phith0n/mooder)
- [fuzz_dict:常用的一些fuzz及爆破字典，欢迎大神继续提供新的字典及分类。](https://github.com/TuuuNya/fuzz_dict)
- [teemo:A Domain Name & Email Address Collection Tool](https://github.com/bit4woo/teemo)
- [reCAPTCHA:自动识别图形验证码并用于burp intruder爆破模块的插件](https://github.com/bit4woo/reCAPTCHA)
- [SuperWeChatPC:超级微信电脑客户端，支持多开、防消息撤销、语音消息备份...开放WeChatSDK](https://github.com/anhkgg/SuperWeChatPC)
- [RGPerson:随机身份生成脚本](https://github.com/gh0stkey/RGPerson)
- [opencanary_web:The web management platform of honeypot](https://github.com/p1r06u3/opencanary_web)
- [一些常用的Python脚本](https://github.com/fupinglee/MyPython)
- [CyberSecurityRSS:优秀的个人情报来源](https://github.com/zer0yu/CyberSecurityRSS)
- [slides:The slides I have ever presented](https://github.com/A7um/slides)
- [mylamour的issues](https://github.com/mylamour/blog/issues)
- [BurpSuite-collections:BurpSuite收集：包括不限于 Burp 文章、破解版、插件(非BApp Store)、汉化等相关教程](https://github.com/Mr-xn/BurpSuite-collections)

