package com.acme.security;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Authenticates a merchant from headers:
 * X-Acme-Merchant, X-Acme-Timestamp (epoch seconds), X-Acme-Signature = hex(HMAC-SHA256(secret, merchant + ":" + timestamp)).
 * Requests without any signature headers pass through unauthenticated (authorization rules decide).
 */
public class SignatureAuthenticationFilter extends OncePerRequestFilter {

    public static final String MERCHANT = "X-Acme-Merchant";
    public static final String TIMESTAMP = "X-Acme-Timestamp";
    public static final String SIGNATURE = "X-Acme-Signature";

    private final AcmeSecurityProperties properties;
    private final ObjectMapper objectMapper;

    public SignatureAuthenticationFilter(AcmeSecurityProperties properties, ObjectMapper objectMapper) {
        this.properties = properties;
        this.objectMapper = objectMapper;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String merchant = request.getHeader(MERCHANT);
        String timestamp = request.getHeader(TIMESTAMP);
        String signature = request.getHeader(SIGNATURE);
        if (merchant == null && timestamp == null && signature == null) {
            chain.doFilter(request, response);
            return;
        }
        String problem = verify(merchant, timestamp, signature);
        if (problem != null) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            objectMapper.writeValue(response.getOutputStream(), Map.of("error", "invalid_signature", "detail", problem));
            return;
        }
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(merchant, null,
                List.of(new SimpleGrantedAuthority("ROLE_MERCHANT"))));
        chain.doFilter(request, response);
    }

    private String verify(String merchant, String timestamp, String signature) {
        if (merchant == null || timestamp == null || signature == null) {
            return "missing signature headers";
        }
        try {
            Duration skew = Duration.between(Instant.ofEpochSecond(Long.parseLong(timestamp)), Instant.now()).abs();
            if (skew.compareTo(properties.getMaxClockSkew()) > 0) {
                return "timestamp outside allowed clock skew";
            }
        }
        catch (NumberFormatException ex) {
            return "bad timestamp";
        }
        String expected = sign(properties.getSigningSecret(), merchant, timestamp);
        return MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8), signature.getBytes(StandardCharsets.UTF_8))
                ? null : "signature mismatch";
    }

    public static String sign(String secret, String merchant, String timestamp) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return HexFormat.of().formatHex(mac.doFinal((merchant + ":" + timestamp).getBytes(StandardCharsets.UTF_8)));
        }
        catch (GeneralSecurityException ex) {
            throw new IllegalStateException(ex);
        }
    }
}
