package com.example.simplesociallogin.controller;

import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
@RequestMapping
public class HomeController {

    @GetMapping
    public String welcome(){
        return "welcome";
    }

    @GetMapping("/user")
    public Principal user(Principal principal, OAuth2AuthenticationToken token){
        System.out.println(token.getPrincipal().getAttributes());
        return principal;
    }
}
