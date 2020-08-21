package com.example.wso2.oidc.demo.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

//@Configuration
public class OAuth2Config {// extends WebSecurityConfigurerAdapter{
	
	/*@Override
	protected void configure(HttpSecurity http) throws Exception {		
		http.cors().and().csrf().disable()  
        .authorizeRequests()
            .antMatchers("/resources/**", "/registration").permitAll()
            .antMatchers(HttpMethod.POST, "/auth/wso2").permitAll()
            .antMatchers(HttpMethod.POST, "/login").permitAll()
            .anyRequest().authenticated()
            .and()
        .formLogin()
            .loginPage("/login")
            .permitAll()
            .and()
        .logout()
            .permitAll();
	}*/
	
}
