package com.example.wso2.oidc.demo.controller;

import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class IndexController {
    @GetMapping(value ="/")
    public String getUserName(Model model, OAuth2AuthenticationToken token) {
    	DefaultOidcUser dOidUser = (DefaultOidcUser)token.getPrincipal();
        model.addAttribute("userName", token.getPrincipal().getName());
        model.addAttribute("idtoken", dOidUser.getIdToken().getTokenValue());
        return "userinfo";
    }
}