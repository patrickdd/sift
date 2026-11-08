package com.example.flightoffers;

import java.math.BigDecimal;
import java.util.List;
import java.util.regex.Pattern;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
public class OfferService {

    private static final Pattern IATA_CODE = Pattern.compile("[A-Z]{3}");

    private final OfferRepository repository;

    public OfferService(OfferRepository repository) {
        this.repository = repository;
    }

    public List<Offer> search(String origin, String destination, String carrier, BigDecimal maxPrice) {
        return repository.search(requireIata(origin), requireIata(destination), carrier, maxPrice);
    }

    public Offer getById(long id) {
        return repository.findById(id).orElseThrow(() -> new OfferNotFoundException(id));
    }

    public Offer create(Offer offer) {
        requireIata(offer.origin());
        requireIata(offer.destination());
        return repository.save(offer);
    }

    private static String requireIata(String code) {
        if (code == null || !IATA_CODE.matcher(code).matches()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Expected a three-letter airport code");
        }
        return code;
    }
}
