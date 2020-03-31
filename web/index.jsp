<%--
  Created by IntelliJ IDEA.
  User: yorick
  Date: 2020/3/30
  Time: 18:36
  To change this template use File | Settings | File Templates.
--%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html>
  <head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>SM2国密算法测试</title>
    <link href="css/bootstrap.min.css" rel="stylesheet">
    <script src="js/jquery-3.4.1.js"></script>
    <script src="js/bootstrap.min.js"></script>
  </head>
  <script type="text/javascript">
  </script>
  <body>
    <center>
      <h3>1.生成密钥对</h3>
      <hr>
      <form action="${pageContext.request.contextPath}/generateKeyPairServlet" method="post">
        <button type="submit" class="btn btn-primary">点我,生成密钥对</button>
      </form>
      <p class="bg-success">
        公钥：${keyPair[0]}
        <br>私钥：${keyPair[1]}
      </p>
    </center>

    <hr>
    <center>
      <h3>2.由服务器生成密文</h3>
      <hr>
      <form action="${pageContext.request.contextPath}/encryptServlet" method="post">
        <div class="form-group">
          <label for="data">请输入数据</label>
          <input type="text" class="form-control" id="data" name="data" value="${data}" placeholder="请输入加密字符串，不输入的话有惊喜">
        </div>
        <div class="form-group">
          <label for="publicK">请输入公钥</label>
          <input type="text" class="form-control" id="publicK" name="publicKey" value="${publicKey}" placeholder="请输入公钥">
        </div>
        <button type="submit" class="btn btn-primary">提交生成密文</button>
      </form>

      <p class="bg-warning">
        ${msg_e}
      </p>
      <dl>
        <dt>密文：</dt>
        <dd>
          <textarea rows="10" cols="60">
            ${encryptSentence}
          </textarea>
        </dd>
      </dl>



    </center>
    <hr>
    <center>
      <h3>3.解密，应该在本地客户端解密，为了方便操作也将解密加到服务器里面了</h3>
      <hr>
      <form action="${pageContext.request.contextPath}/decryptServlet" method="post">
        <div class="form-group">
          <label for="encryptData">请输入密文</label>
          <input type="text" class="form-control" id="encryptData" name="encryptData" value="${encryptData}" placeholder="请输入密文">
        </div>
        <div class="form-group">
          <label for="privateK">请输入私钥</label>
          <input type="text" class="form-control" id="privateK" name="privateKey" value="${privateKey}" placeholder="请输入私钥">
        </div>
        <button id="submitId" type="submit" class="btn btn-primary">提交解密</button>
      </form>
      <p class="bg-warning">
        ${msg}
      </p>
      <p class="bg-success">
        明文：${decryptSentence}
      </p>
    </center>



  </body>
</html>
