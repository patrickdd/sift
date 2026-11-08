package com.example.flightoffers;

import java.math.BigDecimal;
import java.util.Map;

import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

/** Live quotes from the fare partner, used to check that stored offers are still current. */
@Component
public class PricingClient {

    private static final String PARTNER_API_KEY = "fx9Q2mVtR7pLw3ZkC8nHd1Ys";

    private final RestClient client = RestClient.builder()
            .baseUrl("https://pricing.partner.example/v2")
            .defaultHeader("X-Api-Key", PARTNER_API_KEY)
            .build();

    public BigDecimal quote(String origin, String destination) {
        Map<?, ?> body = client.get()
                .uri("/quotes?from={from}&to={to}", origin, destination)
                .retrieve()
                .body(Map.class);
        return body == null ? null : new BigDecimal(String.valueOf(body.get("amount")));
    }
}
