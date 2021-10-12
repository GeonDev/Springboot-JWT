package com.example.jwt.filter;

import java.util.Date;
import com.example.jwt.auth.PrincipalDetail;
import com.example.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

//로그인을 하고 JWT토큰을 생성해주는 필터(인증 요청이 있을때 작동)
//스프링 시큐리티 필터가 username. password 전송시 작동함
//내가 강제로 필터를 등록할때 AuthenticationManager를 요구함
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JWT 로그인 필터 접근");

        try {
            //JSON을 파싱 하여 유저 클래스에 넣어줌
            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(), User.class);

            //토큰 생성
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            //PrincipalDetailService의 loadUserByUsername 실행 -> 로그인 성공시 authentication 리턴
            Authentication authentication = authenticationManager.authenticate(authenticationToken);

            //정상적으로 로그인이 되었는지 데이터를 꺼내어 확인 할수 있다.
            //PrincipalDetail principalDetail = (PrincipalDetail)authentication.getPrincipal();
            //System.out.println(principalDetail.getUser().getUsername());

            //authentication 객체를 return하면 세션에 저장된다.(권한 관리를 편하게 하기 위해 사용)
            return authentication;

        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    // attemptAuthentication 인증이 정상적으로 실행된 이후에 실행됨
    // JWT 토큰을 만들어서 request한 사용자에게 JWT를 전달
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        PrincipalDetail principalDetail = (PrincipalDetail)authResult.getPrincipal();

        String jwtToken = JWT.create()
                //토큰의 이름 -> 큰 의미는 없다.
                .withSubject(principalDetail.getUsername())
                //만료 시간 -> 보통 10초로 잡음
                .withExpiresAt(new Date(System.currentTimeMillis()+(60000)*30))
                //토큰에 넣을 값
                .withClaim("id", principalDetail.getUser().getId())
                .withClaim("username", principalDetail.getUser().getUsername())
                //서버 비밀키 hash 암호화 사용
                .sign(Algorithm.HMAC512("cos"));

        response.addHeader("Authorization", "Bearer "+jwtToken);
    }
}
