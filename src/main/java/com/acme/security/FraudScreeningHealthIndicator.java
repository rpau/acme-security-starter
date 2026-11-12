package com.acme.security;

import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;

public class FraudScreeningHealthIndicator implements HealthIndicator {

    private final FraudScreeningService service;

    public FraudScreeningHealthIndicator(FraudScreeningService service) {
        this.service = service;
    }

    @Override
    public Health health() {
        return Health.up().withDetail("threshold", service.threshold()).build();
    }
}
