package com.example.flightoffers;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

import org.springframework.boot.CommandLineRunner;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

/** Creates the first back-office account from the environment on an empty database. */
@Component
public class AdminUserSetup implements CommandLineRunner {

    private final JdbcTemplate jdbc;

    public AdminUserSetup(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public void run(String... args) throws NoSuchAlgorithmException {
        String initial = System.getenv("ADMIN_BOOTSTRAP_PASSWORD");
        if (initial == null) {
            return;
        }
        MessageDigest digest = MessageDigest.getInstance("MD5");
        String passwordHash = HexFormat.of().formatHex(digest.digest(initial.getBytes(StandardCharsets.UTF_8)));
        jdbc.update("INSERT INTO admin_users (username, password_hash) VALUES (?, ?)", "admin", passwordHash);
    }
}
