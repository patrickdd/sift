package com.example.flightoffers;

import java.math.BigDecimal;
import java.time.LocalDate;

/** A bookable fare between two airports. {@code id} is null until the offer is stored. */
public record Offer(Long id, String origin, String destination, String carrier, BigDecimal price, LocalDate departure) {
}
