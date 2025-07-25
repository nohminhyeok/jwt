package com.example.jwt.controller;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.jwt.dto.UserAddForm;
import com.example.jwt.service.UserService;

@RestController
public class UserController {
    private final UserService userService;
    public UserController(UserService userService) {       
        this.userService = userService;
    }

    @PostMapping("/addUser")
    public String addUser(UserAddForm userAddForm) {
        System.out.println(userAddForm.getUsername());
        userService.joinProcess(userAddForm);
        return "회원가입성공";
    }
}