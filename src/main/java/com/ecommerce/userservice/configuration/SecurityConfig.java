    package com.ecommerce.userservice.configuration;

    import java.security.KeyPair;
    import java.security.KeyPairGenerator;
    import java.security.interfaces.RSAPrivateKey;
    import java.security.interfaces.RSAPublicKey;
    import java.util.UUID;

    import com.nimbusds.jose.jwk.JWKSet;
    import com.nimbusds.jose.jwk.RSAKey;
    import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
    import com.nimbusds.jose.jwk.source.JWKSource;
    import com.nimbusds.jose.proc.SecurityContext;

    import org.springframework.context.annotation.Bean;
    import org.springframework.context.annotation.Configuration;
    import org.springframework.core.annotation.Order;
    import org.springframework.http.MediaType;
    import org.springframework.security.config.Customizer;
    import org.springframework.security.config.annotation.web.builders.HttpSecurity;
    import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
    import org.springframework.security.core.userdetails.User;
    import org.springframework.security.core.userdetails.UserDetails;
    import org.springframework.security.core.userdetails.UserDetailsService;
    import org.springframework.security.oauth2.core.AuthorizationGrantType;
    import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
    import org.springframework.security.oauth2.core.oidc.OidcScopes;
    import org.springframework.security.oauth2.jwt.JwtDecoder;
    import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
    import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
    import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
    import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
    import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
    import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
    import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
    import org.springframework.security.provisioning.InMemoryUserDetailsManager;
    import org.springframework.security.web.SecurityFilterChain;
    import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
    import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

    @Configuration
    @EnableWebSecurity
    public class SecurityConfig {

        @Bean
        @Order(1) // assigns a priority to beans, with lower values indicating higher priority (executed earlier).
        public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
                throws Exception {
            // A Spring Security filter chain for the Protocol Endpoints - OAuth2 Authorization Endpoint
            OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                    OAuth2AuthorizationServerConfigurer.authorizationServer();

            http
                    .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                    .with(authorizationServerConfigurer, (authorizationServer) ->
                            authorizationServer
                                    .oidc(Customizer.withDefaults())	// Enable OpenID Connect 1.0
                    )
//                    .authorizeHttpRequests((authorize) ->
//                            authorize
//                                    .anyRequest().authenticated()
//                    )
                    // Redirect to the login page when not authenticated from the
                    // authorization endpoint
                    .exceptionHandling((exceptions) -> exceptions
                            .defaultAuthenticationEntryPointFor(
                                    new LoginUrlAuthenticationEntryPoint("/login"),
                                    new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                            )
                    );

            return http.build();
        }

        @Bean
        @Order(2)
        // A Spring Security filter chain for authentication.
        public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
                throws Exception {

            http
                    .authorizeHttpRequests((authorize) -> authorize
                            .anyRequest().permitAll()
                    )
                    // Disable Cross-Origin Resource Sharing (CORS) and Cross-Site Request Forgery (CSRF) protection
                    .cors().disable()
                    .csrf().disable()
                    // Form login handles the redirect to the login page from the
                    // authorization server filter chain
                    .formLogin(Customizer.withDefaults());

            return http.build();
        }

        // Commenting becuase we're going to use the database to store users data - Model - Client

//        @Bean
//        // An instance of UserDetailsService for retrieving users to authenticate.
//        public UserDetailsService userDetailsService() {
//            UserDetails userDetails = User.withDefaultPasswordEncoder()
//                    .username("user")
//                    .password("password")
//                    .roles("USER")
//                    .build();
//
//            return new InMemoryUserDetailsManager(userDetails);
//        }

        // Commenting because we need to store the client data in the database and also the same has been
        // generated in the JpaRegisteredClientRepository.java

//        @Bean
//        // An instance of RegisteredClientRepository for managing clients.
//        // Here client is the user who is accessing the application.
//        public RegisteredClientRepository registeredClientRepository() {
//            RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
//                    .clientId("oidc-client")
//                    .clientSecret("{noop}secret")
//                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
//                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
//                    .redirectUri("http://127.0.0.1:8080/login/oauth2/code/oidc-client")
//                    .postLogoutRedirectUri("http://127.0.0.1:8080/")
//                    .scope(OidcScopes.OPENID)
//                    .scope(OidcScopes.PROFILE)
//                    .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
//                    .build();
//
//            return new InMemoryRegisteredClientRepository(oidcClient);
//        }

        @Bean
        // An instance of com.nimbusds.jose.jwk.source.JWKSource for signing access tokens.
        public JWKSource<SecurityContext> jwkSource() {
            KeyPair keyPair = generateRsaKey();
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
            RSAKey rsaKey = new RSAKey.Builder(publicKey)
                    .privateKey(privateKey)
                    .keyID(UUID.randomUUID().toString())
                    .build();
            JWKSet jwkSet = new JWKSet(rsaKey);
            return new ImmutableJWKSet<>(jwkSet);
        }

        // An instance of java.security.KeyPair with keys generated on startup used to create the JWKSource above.
        private static KeyPair generateRsaKey() {
            KeyPair keyPair;
            try {
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
                keyPairGenerator.initialize(2048);
                keyPair = keyPairGenerator.generateKeyPair();
            }
            catch (Exception ex) {
                throw new IllegalStateException(ex);
            }
            return keyPair;
        }

        @Bean
        // An instance of JwtDecoder for decoding signed access tokens.
        public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
            return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
        }

        @Bean
        // An instance of AuthorizationServerSettings to configure Spring Authorization Server.
        public AuthorizationServerSettings authorizationServerSettings() {
            return AuthorizationServerSettings.builder().build();
        }

    }