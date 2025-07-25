package com.example.jwt.security;

import java.io.IOException;
import java.util.Collection;
import java.util.Iterator;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.example.jwt.dto.CustomUserDetails;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class JWTLoginFilter extends UsernamePasswordAuthenticationFilter {
	//JWTUtil 주입
	private final JWTUtil jwtUtil;
    private final AuthenticationManager authenticationManager;
    public JWTLoginFilter(AuthenticationManager authenticationManager, JWTUtil jwtUtil) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
    }

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, 
												HttpServletResponse response) throws org.springframework.security.core.AuthenticationException {
		String username = obtainUsername(request);
        String password = obtainPassword(request);
        System.out.println("▶▶▶▶▶"+ username + "/" + password);
        
        
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password, null);
		//token에 담은 검증을 위한 AuthenticationManager로 전달
        return authenticationManager.authenticate(authToken);
	}
	// Authentication authResult 인자값으로 로그인 성공 정보를 전달
	//로그인 성공시 실행하는 메소드 - JWT토큰 발급
	@Override
	protected void successfulAuthentication(HttpServletRequest request, 
											HttpServletResponse response, 
											FilterChain chain,
											Authentication authResult) throws IOException, ServletException {
		// JWT 토큰 발급 로직 -> JWTUtil.class 호출	
		CustomUserDetails customUserDetails = (CustomUserDetails)authResult.getPrincipal();
        String username = customUserDetails.getUsername();

        Collection<? extends GrantedAuthority> authorities = authResult.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();
        String role = auth.getAuthority();
        String token = jwtUtil.createJwt(username, role);
        System.out.println(token);
        
        response.addHeader("Authorization", "Bearer " + token); // 
	}

	//로그인 실패시 실행하는 메소드 - 인증실패 메세지 응답
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, 
    											HttpServletResponse response,
    											org.springframework.security.core.AuthenticationException failed) throws IOException, ServletException {
    	System.out.println("로그인 실패");
    	response.setStatus(401);
    }
}