package com.example.flightoffers;

import java.util.Map;

import java.io.IOException;
import java.math.BigDecimal;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/admin")
public class AdminController {

    private final JdbcTemplate jdbc;
    private final FareCsvLoader fares;

    public AdminController(JdbcTemplate jdbc, FareCsvLoader fares) {
        this.jdbc = jdbc;
        this.fares = fares;
    }

    @GetMapping("/fares")
    public Map<String, BigDecimal> fares() throws IOException {
        return fares.load();
    }

    @GetMapping("/stats")
    public Map<String, Long> stats() {
        Long offers = jdbc.queryForObject("SELECT COUNT(*) FROM offers", Long.class);
        return Map.of("offers", offers == null ? 0L : offers);
    }
}
