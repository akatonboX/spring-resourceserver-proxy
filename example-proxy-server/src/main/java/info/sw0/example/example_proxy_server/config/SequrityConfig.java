package info.sw0.example.example_proxy_server.config;

import org.springframework.context.annotation.Bean;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity(debug = true)
public class SequrityConfig {

  @Bean
  SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http.authorizeRequests()
    .mvcMatchers("/test/**").permitAll()
    .anyRequest().authenticated();
    http.oauth2Login();

    return http.build();
  }

}
