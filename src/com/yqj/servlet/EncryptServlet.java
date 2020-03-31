package com.yqj.servlet;

import com.yqj.service.AlgorithmService;
import com.yqj.service.impl.AlgorithmServiceImpl;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@WebServlet("/encryptServlet")
public class EncryptServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        //设置编码
        request.setCharacterEncoding("utf-8");
        response.setContentType("text/html;charset=utf-8");
        //获取参数
        //获取公钥
        String publicKey = request.getParameter("publicKey");
        //获取加密数据
        String data = request.getParameter("data");

        //异常处理
        if(publicKey==null || "".equals(publicKey)){
            request.setAttribute("msg_e","请输入公钥");
            request.getRequestDispatcher("/index.jsp").forward(request,response);
        }

        //调用service的生成密文方法
        AlgorithmService service = new AlgorithmServiceImpl();
        String encryptSentence = service.encodingByPublicKey(data, publicKey);
        //存储转发
        HttpSession session = request.getSession();
        session.setAttribute("encryptSentence",encryptSentence);
        session.setAttribute("data",data);
        session.setAttribute("publicKey",publicKey);
        request.getRequestDispatcher("/index.jsp").forward(request,response);
    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        this.doPost(request, response);
    }
}
