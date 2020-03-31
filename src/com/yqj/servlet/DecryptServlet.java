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


@WebServlet("/decryptServlet")
public class DecryptServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        //设置编码
        request.setCharacterEncoding("utf-8");
        response.setContentType("text/html;charset=utf-8");
        //接收密文
        String encryptData = request.getParameter("encryptData");
        //接收私钥
        String privateKey = request.getParameter("privateKey");

        //异常处理
        if(privateKey==null || "".equals(privateKey) || encryptData==null || "".equals(encryptData)){
            request.setAttribute("msg","请输入密文和私钥");
            request.getRequestDispatcher("/index.jsp").forward(request,response);
        }

        //调用service解密方法
        AlgorithmService service = new AlgorithmServiceImpl();
        String decriptSentence = service.decodingByPrivateKey(encryptData, privateKey);

        //存储转发
        HttpSession session = request.getSession();
        session.setAttribute("decryptSentence",decriptSentence);
        session.setAttribute("encryptData",encryptData);
        session.setAttribute("privateKey",privateKey);
        request.getRequestDispatcher("/index.jsp").forward(request,response);


    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        this.doPost(request, response);
    }
}
