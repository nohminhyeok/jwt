package com.example.jwt.security;


import java.nio.charset.StandardCharsets;
import java.util.Date;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.stereotype.Component;

import io.jsonwebtoken.Jwts;

// JWT버전마다 토큰 발급 코드가 다르다! 
// JWT 0.12.x버전
@Component
public class JWTUtil {
    private SecretKey secretKey;
    public JWTUtil() {
    	// 키문자열은 소스코드에 포함시키면 github에 공유시 노출되므로, application.properties파일에 변수로 설정하고 불러와서 사용을 권장
    	// 키문자열의 길이는 256비트(32바이트) 이상 - 영문자는 32문자이상
    	String strKey = "goodee-academy-0123456789-GOODEE-ACADEMY"; 
        secretKey = new SecretKeySpec(strKey.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
    }
    
    // 발급된 JWT토큰은 발급 서버측에서 확인 가능한 정보를 포함(우리서버에서 발급한 토큰이 맞음을 증명하는 암호화된 정보)   
    // 외부로 노출될 수도 있으니 비밀번호같은 개인정보는 포함시키지 않음.  
    public String getUsername(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("username", String.class);
    }

    public String getRole(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("role", String.class);
    }

    public Boolean isExpired(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().getExpiration().before(new Date());
    }

    public String createJwt(String username, String role) {
        return Jwts.builder()
                .claim("username", username)
                .claim("role", role)
                .issuedAt(new Date(System.currentTimeMillis()))
                // 10*60*1000 ms -> 10분
                .expiration(new Date(System.currentTimeMillis() + 10*60*1000))
                .signWith(secretKey)
                .compact();
    }
}