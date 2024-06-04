package fr.poc.template.config.security;

import org.keycloak.adapters.authorization.integration.jakarta.ServletPolicyEnforcerFilter;
import org.keycloak.representations.adapters.config.PolicyEnforcerConfig;
import org.keycloak.util.JsonSerialization;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;

import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

    /**
     * Configure the security filter chain.
     *
     * @param http the {@link HttpSecurity} to use
     * @return the {@link SecurityFilterChain}
     * @throws Exception if an error occurs
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable);
        http.addFilterAfter(createPolicyEnforcerFilter(), BearerTokenAuthenticationFilter.class);
        http.sessionManagement(
                t -> t.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        );

        return http.build();
    }

    /**
     * Create a {@link ServletPolicyEnforcerFilter} based on the configuration file `keycloak.json`.
     *
     * @return the filter
     */
    private ServletPolicyEnforcerFilter createPolicyEnforcerFilter() throws IOException {
        PolicyEnforcerConfig config = JsonSerialization.readValue(getClass().getResourceAsStream("/config/keycloak/keycloak.json"),
                PolicyEnforcerConfig.class);

        return new ServletPolicyEnforcerFilter(request -> config);
    }

}
