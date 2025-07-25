package com.example.jwt.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
	// JWTLoginFilter 생성자가 JWTUtil타입을 전달받아야 하기에
	// JWTUtil 주입
	private final JWTUtil jwtUtil;
	
    //AuthenticationManager가 인자로 받을 AuthenticationConfiguraion 객체 생성자 주입
    private final AuthenticationConfiguration authenticationConfiguration;
    public SecurityConfig(AuthenticationConfiguration authenticationConfiguration, JWTUtil jwtUtil) {
        this.authenticationConfiguration = authenticationConfiguration;
        this.jwtUtil = jwtUtil;
    }

    //AuthenticationManager Bean 등록
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }
	
	
	@Bean
	public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {

		// csrf disable
		httpSecurity.csrf((configurer) -> configurer.disable());

		// From 로그인 방식 disable
		httpSecurity.formLogin((configurer) -> configurer.disable());

		// http basic 인증 방식 disable
		httpSecurity.httpBasic((configurer) -> configurer.disable());

		// 경로별 인가 작업
		httpSecurity.authorizeHttpRequests((matcherRegistry) -> 
				matcherRegistry.requestMatchers("/login", "/", "/addUser").permitAll()
								.requestMatchers("/admin").hasRole("ADMIN")
								.anyRequest().authenticated());

		// 토큰을 가진 요청이라면 인증이 필요가 없으니 JWTLoginFilter 앞에 토큰 검증 필터 등록
		httpSecurity.addFilterBefore(new JWTRequestFilter(jwtUtil), JWTLoginFilter.class);
		
		// 재정의 한 JWTLoginFilter 등록
		httpSecurity.addFilterAt(new JWTLoginFilter(this.authenticationManager(this.authenticationConfiguration), this.jwtUtil), 
								UsernamePasswordAuthenticationFilter.class);
		
		// 세션 설정
		httpSecurity.sessionManagement((configurer) -> configurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

		return httpSecurity.build();
	}
	@Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }
}