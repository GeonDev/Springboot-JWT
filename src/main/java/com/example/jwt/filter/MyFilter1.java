package com.example.jwt.filter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class MyFilter1 implements Filter {
    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        System.out.println("필터 1");

        HttpServletRequest req = (HttpServletRequest) servletRequest;
        HttpServletResponse res = (HttpServletResponse) servletResponse;

       
        if(req.getMethod().equals("POST")){
            String headerAuth =  req.getHeader("Authrization");
            System.out.println("headerAuth(POST) : "+ headerAuth);

            //토큰의 이름이 COS 일때만 필터가 이어짐
            if(headerAuth.equals("COS")){
                filterChain.doFilter(req, res);
            }else{
                PrintWriter out = res.getWriter();
                System.out.println("인증 안됨");
            }
        }
    }
}
