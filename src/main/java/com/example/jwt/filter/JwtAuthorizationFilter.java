package com.example.jwt.filter;

import com.auth0.jwt.algorithms.Algorithm;
import com.example.jwt.auth.PrincipalDetail;
import com.example.jwt.model.User;
import com.example.jwt.repository.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

//시큐리티 필터중 BasicAuthenticationFilter를 사용
//권한, 인증이 필요한 주소를 요청하였을 경우 해당 필터를 타게된다.
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private UserRepository userRepository;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
        super(authenticationManager);
        this.userRepository = userRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {

        String jwtHeader = request.getHeader("Authorization");

        if(jwtHeader == null || !jwtHeader.startsWith("Bearer ")){
            chain.doFilter(request, response);
            return;
        }

        String token = jwtHeader.replace(jwtHeader,"Bearer ");

        String username = JWT.require(Algorithm.HMAC512("cos")).build().verify(token).getClaim("username").asString();

        if(username !=null || !username.equals("")){
            User user = userRepository.findByUsername(username);

            //전달 받은 유저정보로 PrincipalDetail을 생성
            PrincipalDetail principalDetails = new PrincipalDetail(user);

            //JWT토큰 서명을 통하여 서명이 정상이면 객체를 생성한다.
            Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails,null, principalDetails.getAuthorities());

            // 강제로 시큐리티의 세션에 접근하여 값 저장
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }


        super.doFilterInternal(request, response, chain);
    }
}
