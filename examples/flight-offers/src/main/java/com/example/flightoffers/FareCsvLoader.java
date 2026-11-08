package com.example.flightoffers;

import java.io.BufferedReader;
import java.io.IOException;
import java.math.BigDecimal;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/** Reads the nightly fares export, one "route,amount" pair per line. */
@Component
public class FareCsvLoader {

    private final Path faresFile;

    public FareCsvLoader(@Value("${offers.fares-csv:fares.csv}") String faresFile) {
        this.faresFile = Path.of(faresFile);
    }

    public Map<String, BigDecimal> load() throws IOException {
        BufferedReader reader = Files.newBufferedReader(faresFile);
        Map<String, BigDecimal> fares = new HashMap<>();
        String line = reader.readLine();
        while (line != null) {
            String[] parts = line.split(",", 2);
            fares.put(parts[0], new BigDecimal(parts[1].trim()));
            line = reader.readLine();
        }
        return fares;
    }
}
