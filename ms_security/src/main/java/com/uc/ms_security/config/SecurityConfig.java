package com.uc.ms_security.config;

import com.uc.ms_security.authorization.DynamicAuthorizationManager;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final DynamicAuthorizationManager dynamicAuthorizationManager;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http) throws Exception {

        http
                .csrf(csrf -> csrf.disable())
            .cors(Customizer.withDefaults())
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
                .authorizeHttpRequests(auth -> auth
                .requestMatchers(HttpMethod.POST,
                        "/api/auth/login",
                        "/api/auth/2fa/verify",
                        "/api/auth/oauth",
                        "/api/auth/password-recovery",
                        "/api/auth/password-reset")
                .permitAll()
                // Cierre de sesión y ajustes propios: basta un token válido.
                .requestMatchers(HttpMethod.POST, "/api/auth/logout")
                .authenticated()
                .requestMatchers(HttpMethod.PUT, "/api/auth/2fa-settings")
                .authenticated()
                // Registro público: crea el usuario sin roles ni permisos.
                .requestMatchers(HttpMethod.POST, "/api/users")
                .permitAll()
                // Identidad y permisos propios: basta con tener un token válido.
                .requestMatchers(HttpMethod.GET, "/api/auth/me")
                .authenticated()
                .anyRequest()
                .access(dynamicAuthorizationManager)
            )
            .oauth2ResourceServer(resourceServer -> resourceServer
                .jwt(Customizer.withDefaults())
            );

        return http.build();
    }

    /**
     * Permite que el frontend (otro origen) consuma la API desde el navegador.
     * El CorsFilter de Spring Security atiende el preflight antes de la
     * autorización dinámica, por eso OPTIONS no necesita un permiso en la BD.
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource(
            @Value("${security.cors.allowed-origins}") List<String> allowedOrigins) {

        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(allowedOrigins);
        configuration.setAllowedMethods(
                List.of("GET", "POST", "PUT", "DELETE", "OPTIONS")
        );
        configuration.setAllowedHeaders(
                List.of("Authorization", "Content-Type")
        );
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source =
                new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/api/**", configuration);

        return source;
    }
}
