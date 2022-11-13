package info.sw0.example.example_auth_server;

import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.util.function.Supplier;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.context.annotation.Bean;

@Slf4j
@EnableWebSecurity()
public class SecurityConfig {
  HttpSessionSecurityContextRepository va;
  @Bean
  SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
    http.authorizeRequests(authorizeRequests -> {
      authorizeRequests.anyRequest().authenticated();
    });
    http.formLogin(Customizer.withDefaults());
    // http.csrf().disable();
    http.cors();
    return http.build();

    // http.authorizeRequests(
    //   authorizeRequests ->{
    //     authorizeRequests.antMatchers("/login**").permitAll();
    //     authorizeRequests.anyRequest().authenticated();
    //   }
    // );
  
    // http.logout(
    //   logout -> logout
    //   .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
    //   .permitAll()   
    //   .invalidateHttpSession(true) 
    //   .logoutSuccessHandler(new LogoutSuccessHandler(){
    //     @Override
    //     public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response,
    //       Authentication authentication) throws IOException, ServletException {
    //         String redirectUrl = request.getParameter("returnTo");
    //         response.sendRedirect(redirectUrl);
          
    //       }
    //     }
    //   )
    // );
    // return http.build();
  }


  @Bean
  UserDetailsService users() {
    return new InMemoryUserDetailsManager(new UserDetails[] {
      User.withDefaultPasswordEncoder().username("user1").password("password").roles("USER").build(),
      User.withDefaultPasswordEncoder().username("user2").password("password").roles("USER", "read").build(),
      User.withDefaultPasswordEncoder().username("user3").password("password").roles("USER", "write").build()
    });
  }

  
}