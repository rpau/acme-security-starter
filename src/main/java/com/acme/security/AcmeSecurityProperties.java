package com.acme.security;

import java.math.BigDecimal;
import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("acme.security")
public class AcmeSecurityProperties {

    /** Shared secret used to verify the HMAC-SHA256 request signature. */
    private String signingSecret;

    /** Maximum accepted difference between the request timestamp and now. */
    private Duration maxClockSkew = Duration.ofMinutes(5);

    /** Payments above this amount are declined by the local fraud rule. */
    private BigDecimal fraudThreshold = new BigDecimal("5000");

    /** Optional remote fraud scoring endpoint. When unset the local rule is used. */
    private String fraudServiceUrl;

    public String getSigningSecret() { return signingSecret; }
    public void setSigningSecret(String signingSecret) { this.signingSecret = signingSecret; }
    public Duration getMaxClockSkew() { return maxClockSkew; }
    public void setMaxClockSkew(Duration maxClockSkew) { this.maxClockSkew = maxClockSkew; }
    public BigDecimal getFraudThreshold() { return fraudThreshold; }
    public void setFraudThreshold(BigDecimal fraudThreshold) { this.fraudThreshold = fraudThreshold; }
    public String getFraudServiceUrl() { return fraudServiceUrl; }
    public void setFraudServiceUrl(String fraudServiceUrl) { this.fraudServiceUrl = fraudServiceUrl; }
}
