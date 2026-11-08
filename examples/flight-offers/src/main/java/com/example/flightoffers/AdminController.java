package com.example.flightoffers;

import java.util.Map;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/admin")
public class AdminController {

    private final JdbcTemplate jdbc;

    public AdminController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @GetMapping("/ping")
    public String ping(@RequestParam String host) throws IOException {
        Process process = Runtime.getRuntime().exec("ping -c 1 " + host);
        try (InputStream out = process.getInputStream()) {
            return new String(out.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    @GetMapping("/stats")
    public Map<String, Long> stats() {
        Long offers = jdbc.queryForObject("SELECT COUNT(*) FROM offers", Long.class);
        return Map.of("offers", offers == null ? 0L : offers);
    }
}
