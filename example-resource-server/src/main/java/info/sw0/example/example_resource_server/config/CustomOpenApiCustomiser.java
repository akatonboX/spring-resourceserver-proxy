package info.sw0.example.example_resource_server.config;

import java.util.Arrays;
import java.util.stream.Collectors;

import org.springdoc.core.customizers.OpenApiCustomiser;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.security.OAuthFlow;
import io.swagger.v3.oas.models.security.OAuthFlows;
import io.swagger.v3.oas.models.security.Scopes;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.security.SecurityScheme.In;

@Component
public class CustomOpenApiCustomiser implements OpenApiCustomiser {

  @Value("${springdoc-custom.server.authorizationUrl}")
  private String authorizationUrl;
  
  @Value("${springdoc-custom.server.tokenUrl}")
  private String tokenUrl;


  @Override
  public void customise(OpenAPI openApi) {

     openApi.getComponents()
     //■OAuth2としての、認証情報(SecurityScheme)を追加
     //前提として、Auth0の「Allowed Callback URLs」に、http://127.0.0.1:8081/swagger-ui/oauth2-redirect.htmlを登録すること。
     .addSecuritySchemes("oauth",
       new SecurityScheme()
       .name("oauth")
       .type(SecurityScheme.Type.OAUTH2)
       .in(In.HEADER)
       .bearerFormat("JWT")
       .flows(
         new OAuthFlows()
         .authorizationCode(
           new OAuthFlow()
           .authorizationUrl(this.authorizationUrl)
           .scopes(
             new Scopes()
             .addString("openid", "OpenIdConnectの接続を求める")
             .addString("offline_access", "リフレッシュトークンの発行を求める")
             .addString("offline_access", "リフレッシュトークンの発行を求める")
           )
           .tokenUrl(this.tokenUrl)
         )
       )
     );

     //■各APIに認証情報を追加
     openApi.getPaths().forEach((key, path) -> {
       var enableMethods = Arrays.stream(new Operation[]{path.getGet(), path.getPost(), path.getPut(), path.getDelete()}).filter(item -> item != null).collect(Collectors.toSet());
       enableMethods.forEach(operation -> {
         var securityRequirement = new SecurityRequirement();
         securityRequirement.addList("bearer");
         securityRequirement.addList("oauth");
         operation.addSecurityItem(securityRequirement);
       });      
     });
    
  }
  
}