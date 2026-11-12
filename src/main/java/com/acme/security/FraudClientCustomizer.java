package com.acme.security;

import org.springframework.boot.web.client.RestTemplateBuilder;

/**
 * Extension point: applications implement this to tune the HTTP client the starter uses
 * to reach the remote fraud service (timeouts, interceptors, ...).
 */
public interface FraudClientCustomizer {

    RestTemplateBuilder customize(RestTemplateBuilder builder);
}
