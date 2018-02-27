package com.chattypie.config;

import com.appdirect.sdk.security.openid.CustomOpenIdConsumer;
import com.appdirect.sdk.security.openid.service.CustomUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
@Order(101)
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
    private final CustomUserDetailsService customUserDetailsService;
    private final CustomOpenIdConsumer customOpenIdConsumer;

    public SecurityConfiguration(@Autowired CustomUserDetailsService customUserDetailsService,
                                 @Autowired CustomOpenIdConsumer customOpenIdConsumer) {
        this.customUserDetailsService = customUserDetailsService;
        this.customOpenIdConsumer = customOpenIdConsumer;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
            .authorizeRequests()
                .antMatchers("/chatrooms/**")
                .hasAnyRole("ADMIN")
                .and()
            .openidLogin().loginPage("/login/openid").consumer(customOpenIdConsumer).authenticationUserDetailsService(customUserDetailsService)
                .and()
            .logout()
                .logoutSuccessUrl("/")
                .permitAll();
    }
}
