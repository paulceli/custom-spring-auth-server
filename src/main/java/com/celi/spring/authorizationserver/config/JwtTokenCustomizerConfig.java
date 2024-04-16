package com.celi.spring.authorizationserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import static org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames.ID_TOKEN;
import static org.springframework.security.oauth2.server.authorization.OAuth2TokenType.ACCESS_TOKEN;

@Configuration
public class JwtTokenCustomizerConfig {
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        return (context) -> {
            if (!AuthorizationGrantType.CLIENT_CREDENTIALS.equals(context.getAuthorizationGrantType())) {
                if (ID_TOKEN.equals(context.getTokenType().getValue()) || ACCESS_TOKEN.equals(context.getTokenType())) {
                    context.getJwsHeader().type("jwt");
                }
                if (ACCESS_TOKEN.equals(context.getTokenType())) {
                    context.getClaims().claims((claims) -> {
                        claims.put("aud", "my-audience");
                    });
                }
            }
        };
    }
}
