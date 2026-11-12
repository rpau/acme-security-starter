package com.acme.security;

import java.math.BigDecimal;
import java.util.Map;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.web.client.RestTemplate;

/** Decides whether a payment looks fraudulent. Uses a remote scorer if configured, else a local rule. */
public class FraudScreeningService {

    private final AcmeSecurityProperties properties;
    private final RestTemplate restTemplate;

    public FraudScreeningService(AcmeSecurityProperties properties, RestTemplateBuilder builder,
            ObjectProvider<FraudClientCustomizer> customizers) {
        this.properties = properties;
        RestTemplateBuilder configured = builder;
        for (FraudClientCustomizer customizer : customizers.orderedStream().toList()) {
            configured = customizer.customize(configured);
        }
        this.restTemplate = configured.build();
    }

    public FraudDecision screen(String merchantId, BigDecimal amount, String currency) {
        if (properties.getFraudServiceUrl() != null) {
            Integer score = restTemplate.postForObject(properties.getFraudServiceUrl(),
                    Map.of("merchant", merchantId, "amount", amount, "currency", currency), Integer.class);
            int s = score == null ? 100 : score;
            return new FraudDecision(s < 80, s);
        }
        boolean suspicious = amount.compareTo(properties.getFraudThreshold()) > 0;
        return new FraudDecision(!suspicious, suspicious ? 90 : 10);
    }

    public BigDecimal threshold() {
        return properties.getFraudThreshold();
    }
}
