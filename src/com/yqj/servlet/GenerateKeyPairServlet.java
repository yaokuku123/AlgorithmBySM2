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
import java.util.List;

@WebServlet("/generateKeyPairServlet")
public class GenerateKeyPairServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        //设置编码
        request.setCharacterEncoding("utf-8");
        response.setContentType("text/html;charset=utf-8");

        //调用service的获取密钥对方法
        AlgorithmService service = new AlgorithmServiceImpl();
        List<String> keyPair = service.generateKeyPair();
        //存储转发
        HttpSession session = request.getSession();
        session.setAttribute("keyPair",keyPair);
        request.getRequestDispatcher("/index.jsp").forward(request,response);

    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        this.doPost(request, response);
    }
}
