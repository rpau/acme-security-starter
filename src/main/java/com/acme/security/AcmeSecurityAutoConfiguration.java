package com.acme.security;

import com.fasterxml.jackson.databind.ObjectMapper;

import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.http.HttpStatus;

@AutoConfiguration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@EnableConfigurationProperties(AcmeSecurityProperties.class)
public class AcmeSecurityAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public FraudScreeningService fraudScreeningService(AcmeSecurityProperties properties, RestTemplateBuilder builder,
            ObjectProvider<FraudClientCustomizer> customizers) {
        return new FraudScreeningService(properties, builder, customizers);
    }

    @Bean
    @ConditionalOnMissingBean(SecurityFilterChain.class)
    @SuppressWarnings("deprecation")
    public SecurityFilterChain acmeSecurityFilterChain(HttpSecurity http, AcmeSecurityProperties properties,
            ObjectMapper objectMapper) throws Exception {
        // Classic (pre-lambda) DSL: compiles and works on Spring Security 6.x
        http.csrf().disable()
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
            .authorizeRequests()
                .requestMatchers(new AntPathRequestMatcher("/actuator/health/**")).permitAll()
                .anyRequest().hasRole("MERCHANT")
            .and()
            .exceptionHandling().authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
            .and()
            .addFilterBefore(new SignatureAuthenticationFilter(properties, objectMapper),
                    UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(HealthIndicator.class)
    static class FraudHealthConfiguration {

        @Bean
        FraudScreeningHealthIndicator fraudScreeningHealthIndicator(FraudScreeningService service) {
            return new FraudScreeningHealthIndicator(service);
        }
    }
}
