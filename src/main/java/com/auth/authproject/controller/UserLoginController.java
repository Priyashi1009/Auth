package com.auth.authproject.controller;

import com.auth.authproject.service.UserLoginService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@RestController
@RequestMapping("/auth")
public class UserLoginController {

    @Autowired
    private UserLoginService userService;

    @GetMapping("/login")
    public Map<String, String> login(@RequestParam String username, @RequestParam String password) {
        return userService.loginService(username, password);
    }
}
