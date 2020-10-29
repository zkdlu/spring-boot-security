package com.zkdlu.springbootsecurity.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("zkdlu")
                .password("{noop}1234")
                .roles("USER")
            .and()
                .withUser("guest")
                .password("{noop}1234")
                .roles("GUEST");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .headers()
                .frameOptions().sameOrigin()
            .and()
                .formLogin()
            .and()
                .authorizeRequests()
                    .antMatchers("/test/**").hasRole("USER")
                    .anyRequest().permitAll();
    }
}
