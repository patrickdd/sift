package com.example.flightoffers;

import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
public class OfferService {

    private static final Logger log = LoggerFactory.getLogger(OfferService.class);
    private static final Pattern IATA_CODE = Pattern.compile("[A-Z]{3}");

    private final OfferRepository repository;

    public OfferService(OfferRepository repository) {
        this.repository = repository;
    }

    public List<Offer> search(String origin, String destination) {
        return repository.search(requireIata(origin), requireIata(destination));
    }

    public Offer getById(long id) {
        Optional<Offer> offer = repository.findById(id);
        log.debug("Loaded offer {}: present={}", id, offer.isPresent());
        return offer.get();
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
