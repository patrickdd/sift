package com.example.flightoffers;

import java.math.BigDecimal;
import java.time.LocalDate;

/** Identifies offers that are the same fare, whichever partner feed they came from. */
public final class OfferKey {

    private final String carrier;
    private final LocalDate departure;
    private final BigDecimal price;

    private OfferKey(String carrier, LocalDate departure, BigDecimal price) {
        this.carrier = carrier;
        this.departure = departure;
        this.price = price;
    }

    public static OfferKey of(Offer offer) {
        return new OfferKey(offer.carrier(), offer.departure(), offer.price());
    }

    @Override
    public boolean equals(Object other) {
        if (!(other instanceof OfferKey key)) {
            return false;
        }
        return carrier.equals(key.carrier) && departure.equals(key.departure) && price.compareTo(key.price) == 0;
    }
}
