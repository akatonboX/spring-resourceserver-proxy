package info.sw0.example.example_auth_server;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.Collections;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfiguration  {
  private Set<String> redirectUrls = Set.of(
    "http://127.0.0.1:8080/swagger-ui/oauth2-redirect.html",
    "http://127.0.0.1:8081/login/oauth2/code/local"
  );
  @Bean
  @Order(Ordered.HIGHEST_PRECEDENCE)
  public SecurityFilterChain authServerSecurityFilterChain(HttpSecurity http) throws Exception {
    // OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

    var authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer<HttpSecurity>();
		var endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();

      
		http
			.requestMatcher(endpointsMatcher)
			.authorizeRequests(authorizeRequests ->
				authorizeRequests.anyRequest().authenticated()
			)
			.csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
      .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt)
			.apply(authorizationServerConfigurer);



    http.formLogin(Customizer.withDefaults());
    // http.csrf().disable();
    // http.cors();
    // http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
    

    return http.build();
  }

  /**
   * userinfoへのアクセスを可能にするためのDecoder
   * @param jwkSource
   * @return
   */
  @Bean
  JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
    return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
  }

  // @Bean
  // JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
  //   return new JwtDecoderTemp(OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource));
  // }
  // static class JwtDecoderTemp implements JwtDecoder{

  //   private JwtDecoder innerjwtDecoder; 
  //   public JwtDecoderTemp(JwtDecoder innerjwtDecoder){
  //     this.innerjwtDecoder = innerjwtDecoder;
  //   }
  //   @Override
  //   public Jwt decode(String token) throws JwtException {
  //     return this.innerjwtDecoder.decode(token);
  //   }

  // }

  /**
   * リダイレクトURLに設定されたドメインに対し、クロスオリジンを許可する。
   * @return
   */
  @Bean
  private CorsConfigurationSource corsConfigurationSource(){
    var configuration = new CorsConfiguration();
    configuration.addAllowedMethod("GET");
    configuration.addAllowedMethod("POST");
    configuration.addAllowedHeader(CorsConfiguration.ALL);
    this.redirectUrls.forEach(redirectUrl -> {
      try {
        var uri = new URI(redirectUrl);
        var allowUrl = String.format("%s://%s", uri.getScheme(), uri.getAuthority());
        configuration.addAllowedOrigin(allowUrl);
      } catch (URISyntaxException e) {

      }
    });
    // COSR設定を行う範囲のパスを指定する。
    var source = new UrlBasedCorsConfigurationSource();      
    source.registerCorsConfiguration("/**", configuration);
    return source;
  }
  @Bean
  public RegisteredClientRepository registeredClientRepository() {
    RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
      .clientId("client_id")
      .clientSecret("{noop}secret")
      .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
      // .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
      .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
      .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
      .redirectUris(redirectUrls -> redirectUrls.addAll(this.redirectUrls))
      .scope(OidcScopes.OPENID)
      .scope(OidcScopes.PROFILE)
      .scope("offline_access")
      .tokenSettings(TokenSettings.builder()
        .accessTokenTimeToLive(Duration.ofDays(6))
        .refreshTokenTimeToLive(Duration.ofDays(6))
        .reuseRefreshTokens(true).build())
      .build();

    return new InMemoryRegisteredClientRepository(registeredClient);
  }
  
  @Bean
  public JWKSource<SecurityContext> jwkSource() {
    RSAKey rsaKey = generateRsa();
    JWKSet jwkSet = new JWKSet(rsaKey);
    return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
  }

  private static RSAKey generateRsa() {
    KeyPair keyPair = generateRsaKey();
    RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
    RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
    return new RSAKey.Builder(publicKey)
      .privateKey(privateKey)
      .keyID(UUID.randomUUID().toString())
      .build();
  }

  private static KeyPair generateRsaKey() {
    KeyPair keyPair;
    try {
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
      keyPairGenerator.initialize(2048);
      keyPair = keyPairGenerator.generateKeyPair();
    } catch (Exception ex) {
      throw new IllegalStateException(ex);
    }
    return keyPair;
  }

  @Bean
  public ProviderSettings providerSettings() {
    return ProviderSettings.builder()
      .issuer("http://localhost:9000")
      .build();
  }

  /** UserDtailの"ROLE_USER"を除いて、scopeに追加 */
  @Bean 
	public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer(UserDetailsService userDtailesService) {
		return (context) -> {
			if ("access_token".equals(context.getTokenType().getValue())) {
				context.getClaims().claims(claims -> {
          var user = userDtailesService.loadUserByUsername(claims.get("sub").toString());
          var newScopes = user.getAuthorities().stream().map(authority -> authority.getAuthority().substring(5)).filter(authority -> !authority.equals("USER")).collect(Collectors.toSet());

          @SuppressWarnings("unchecked")
          var originalScopes = Optional.ofNullable((Set<String>)claims.get("scope")).orElseGet(() -> Set.of());
          newScopes.addAll(originalScopes);
          claims.put("scope", Collections.unmodifiableSet(newScopes));
        });
			}
		};
  }

}