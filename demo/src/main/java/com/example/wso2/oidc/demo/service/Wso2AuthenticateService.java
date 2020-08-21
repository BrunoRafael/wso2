package com.example.wso2.oidc.demo.service;

import java.util.Arrays;
import java.util.Base64;

import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

@Service
public class Wso2AuthenticateService {
		
	public ResponseEntity<String> authenticate (String clientId, String clientSecret, String username, String password) {
		ResponseEntity<String> response = null;
		RestTemplate restTemplate = new RestTemplate();

		String credentials = clientId + ":" + clientSecret;
		String encodedCredentials = new String(Base64.getEncoder().encodeToString(credentials.getBytes()));

		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
		headers.add("Authorization", "Basic " + encodedCredentials);
		headers.add("Content-Type", "application/x-www-form-urlencoded");
		
		MultiValueMap<String, String> bodyParamMap = new LinkedMultiValueMap<String, String>();
		bodyParamMap.add("grant_type", "password");
		bodyParamMap.add("scope", "test");
		bodyParamMap.add("username", username);
		bodyParamMap.add("password", password);

		HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(bodyParamMap, headers);

		String access_token_url = "https://localhost:9443/oauth2/token";
		//access_token_url += "&grant_type=password&username=" + username + "&password=" + password;
		//access_token_url += "&redirect_uri=http://localhost:9090/home";

		response = restTemplate.exchange(access_token_url, HttpMethod.POST, request, String.class);
		return response;
	}
	
	 public String auth(String clientId, String token, String CallbackUrl, String authzGrantType, 
			 String authzEndpoint, String scope, long lastUpdateSession) {
	 	   
		    OAuthClientRequest.AuthenticationRequestBuilder oAuthAuthenticationRequestBuilder =
		            new OAuthClientRequest.AuthenticationRequestBuilder(authzEndpoint);
		    try {
				oAuthAuthenticationRequestBuilder
				        .setParameter("sessionDataKey", token)
				        .setParameter("relyingParty", clientId)
				        .setParameter("tenantDomain", "carbon.super")
				        .setParameter("_", String.valueOf(lastUpdateSession)).buildBodyMessage();
			} catch (OAuthSystemException e1) {
				e1.printStackTrace();
			}
		   	    
		    try {
		    	OAuthClientRequest authzRequest = oAuthAuthenticationRequestBuilder.buildQueryMessage();
		        return authzRequest.getLocationUri();
		    } catch (OAuthSystemException e) {}
		    
		    return null;
		
		}

}
