/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 */

package com.example.wso2.oidc.demo.controller;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PostMapping;

import com.example.wso2.oidc.demo.model.Wso2ResponseAutentication;
import com.example.wso2.oidc.demo.service.Wso2AuthenticateService;
import com.fasterxml.jackson.databind.ObjectMapper;


public class AuthController {
    /*@GetMapping(value ="/")
    public String getUserName(Model model, OAuth2AuthenticationToken token) {
    	DefaultOidcUser dOidUser = (DefaultOidcUser)token.getPrincipal();
        model.addAttribute("userName", token.getPrincipal().getName());
        model.addAttribute("idtoken", dOidUser.getIdToken().getTokenValue());
        return "userinfo";
    }*/
	
	//@Autowired
	private Wso2AuthenticateService service;
	
	
	private String authzEndpoint="https://localhost:9443/logincontext";
	private String scope="openid";
	private String callBackUrl="http://localhost:9090/home";
	
	private static String CLIENT_PROPERTY_KEY = "spring.security.oauth2.client.registration.wso2.";
	
	//@Autowired
	private Environment env;
	
    //@PostMapping(value ="auth/wso2")
    public String authenticate(Model model, HttpServletRequest request, HttpServletResponse response, HttpSession session) throws IOException {        
        String clientId = env.getProperty(CLIENT_PROPERTY_KEY + "client-id");
        String clientSecret = env.getProperty(CLIENT_PROPERTY_KEY + "client-secret");
		ResponseEntity<String> tokenResponse = service.authenticate(clientId, clientSecret, request.getParameter("username"), request.getParameter("password"));
		
		final Wso2ResponseAutentication wso2Response = new ObjectMapper().readValue(tokenResponse.getBody().getBytes(), Wso2ResponseAutentication.class);
	    
		session.setAttribute("oauth2_grant_type", "password");
	    session.setAttribute("consumer_key", clientId);
	    session.setAttribute("consumer_secret", clientSecret);
	    session.setAttribute("scope", scope);
	    session.setAttribute("sessionDataKey", wso2Response.getAccess_token());
	    session.setAttribute("call_back_url", callBackUrl);
		String uri = this.service.auth(clientId, wso2Response.getAccess_token(),
				(String) session.getAttribute("call_back_url"), 
				(String) session.getAttribute("oauth2_grant_type"),
				authzEndpoint,
				(String) session.getAttribute("scope"), session.getLastAccessedTime());
		
		try {
			response.sendRedirect(uri);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	    model.addAttribute("userName", request.getParameter("username"));
	    model.addAttribute("idtoken", wso2Response.getAccess_token());
		System.out.println("Access Token Response ---------" + tokenResponse.getBody());
		
		
		return "userinfo";
         
    }
}


