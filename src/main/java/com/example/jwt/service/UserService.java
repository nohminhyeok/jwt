package com.example.jwt.service;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.example.jwt.dto.UserAddForm;
import com.example.jwt.entity.User;
import com.example.jwt.repository.UserRepository;

@Service
public class UserService {
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    // 생성자 주입
    public UserService(UserRepository userRepository, BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.userRepository = userRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    public void joinProcess(UserAddForm userAddForm) {

        String username = userAddForm.getUsername();
        String password = userAddForm.getPassword();

        Boolean isExist = userRepository.existsByUsername(username);

        if (isExist) {
        	System.out.println("이름 중복");
            return;
        }

        User data = new User();
        data.setUsername(username);
        data.setPassword(bCryptPasswordEncoder.encode(password));
        // role은 ROLE_ADMIN 입력
        data.setRole("ROLE_ADMIN"); // Spring Security role 은 "ROLE_"로 시작하여야 한다.

        userRepository.save(data);
    }
}