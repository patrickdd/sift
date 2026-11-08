package com.example.flightoffers;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/** Builds HTTP ETag values for offer responses. */
final class OfferEtag {

    private OfferEtag() {
    }

    /**
     * Not a security control: MD5 is only a fast content fingerprint for the HTTP cache. The input is the
     * public offer itself, and a collision at worst serves a stale cached copy.
     */
    static String cacheKeyFor(Offer offer) {
        try {
            MessageDigest cacheKeyDigest = MessageDigest.getInstance("MD5");
            return HexFormat.of().formatHex(cacheKeyDigest.digest(offer.toString().getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("MD5 is required on every JVM", e);
        }
    }
}
