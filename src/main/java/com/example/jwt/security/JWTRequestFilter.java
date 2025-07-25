package com.example.jwt.security;

import java.io.IOException;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import com.example.jwt.dto.CustomUserDetails;
import com.example.jwt.entity.User;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class JWTRequestFilter extends OncePerRequestFilter {
    private final JWTUtil jwtUtil;
    public JWTRequestFilter(JWTUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {			
		//request에서 Authorization 헤더를 찾음
        String authorization= request.getHeader("Authorization");
				
		//Authorization 헤더 검증
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            System.out.println("token null");
            filterChain.doFilter(request, response);	
			// 토큰이 없거나 다른토큰이면 종료(종료하면 다음필터로 넘어감)
            return;
        }
			
        System.out.println("authorization now");
		//토큰에서 Bearer문자 제거 후 토큰문자만 추출
        String token = authorization.split(" ")[1];			
		//토큰 소멸 시간 검증
        if (jwtUtil.isExpired(token)) {
            System.out.println("token expired");
            filterChain.doFilter(request, response);
            // 기간이 지난 토큰이면 종료
            return;
        }

		//토큰에서 username과 role 획득
        String username = jwtUtil.getUsername(token); // ~님 반갑습니다
        String role = jwtUtil.getRole(token); // role에 따른 인가 작업 위한
				
		//userEntity를 생성하여 값 set
        User user = new User();
        user.setUsername(username);
        user.setPassword(""); // 패스워드는 JWT토큰에서는 필요없기에 아무값이나
        user.setRole(role);
				
		//UserDetails에 회원 정보 객체 담기
        CustomUserDetails customUserDetails = new CustomUserDetails(user);

		//스프링 시큐리티 인증 토큰 생성
        Authentication authToken = new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities());
		//세션에 사용자 등록
        SecurityContextHolder.getContext().setAuthentication(authToken);

        filterChain.doFilter(request, response);
    }
}