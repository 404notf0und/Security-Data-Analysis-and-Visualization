# Security-Data-Analysis-and-Visualization
## 2018-2020青年安全圈-活跃技术博主/博客

### Why
- **最初目的**：个人日常安全阅读资源不足，需要从博客、Github、Twitter等多个数据源补充。
- **延续目的**：以人为核心，系统化收集博客、Github、当前主要研究方向、所属安全组织、学校、公司、RSS、知乎、微博、Email等信息，缩小安全圈的范围。
  - **信息检索**：通过关键字检索，方便找人，缩小人与人之间的交流障碍。比如通过高校关键字，可以快速找到校友，通过网络ID快速找到博主。
  - **内容学习**：例如从主要研究方向入手，Follow不同方向活跃博主，补充阅读资源，紧追安全前沿。
  - **数据分析**：挖掘人与人之间的社交网络，判断自己当前所处位置，指引未来发展方向。
### What
1. **数据采集**

	此版本数据为采集到的公开数据，数据格式为：

    	Follow,Star,ID,Security_ID,Blog，Individual_Team_Company，Friend_Link_ID，Github，Weibo，Focus_On，Team，School_Company，Skills_Tags，Man_Tags，RSS，Twitter，Zhihu，Email，Contact，Famous_Projects
	对应的解释分别是：

		笔者在跟着学习的，笔者觉得不错推荐的，索引ID，网络ID，博客链接，个人(1)/团队(2)/公司(3)博客，友情链接的索引ID，Github地址，微博地址，主要研究领域，所属安全团队，所属高校/公司，技能标签（PHP？Python？Java），人物标签（摄影？动漫？文艺），RSS订阅地址，推特地址，知乎地址，邮箱地址，联系方式（QQ？微信？），著名开源项目

	采集到的Skillgs_Tags，Man_Tags，Zhihu三个字段数据很少且意义不大，故计划舍弃。
2. **数据缺失补全**

	通过挖掘人与人之间的社交关系，补全部分数据，此版本数据暂时不会公开。

### How&&Do
* **数据缺失补全**

### Result
* 输出一份价值较高的原始数据和分析结果，使用者以此可以达到信息检索、内容学习、纵观安全的目的。

### 声明
* 所有数据均来自且仅来自公开信息，未加入个人先验知识，如有疑义，请及时联系root@4o4notfound.org。
