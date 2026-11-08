package com.example.flightoffers;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.simple.SimpleJdbcInsert;
import org.springframework.stereotype.Repository;

@Repository
public class OfferRepository {

    private static final String SELECT_OFFER =
            "SELECT id, origin, destination, carrier, price, departure FROM offers";

    private static final RowMapper<Offer> OFFER_MAPPER = (rs, rowNum) -> new Offer(
            rs.getLong("id"),
            rs.getString("origin"),
            rs.getString("destination"),
            rs.getString("carrier"),
            rs.getBigDecimal("price"),
            rs.getDate("departure").toLocalDate());

    private final JdbcTemplate jdbc;
    private final SimpleJdbcInsert insert;

    public OfferRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
        this.insert = new SimpleJdbcInsert(jdbc).withTableName("offers").usingGeneratedKeyColumns("id");
    }

    public List<Offer> search(String origin, String destination, String carrier, BigDecimal maxPrice) {
        StringBuilder sql = new StringBuilder(SELECT_OFFER).append(" WHERE origin = ? AND destination = ?");
        List<Object> args = new ArrayList<>(List.of(origin, destination));
        if (carrier != null) {
            sql.append(" AND carrier = ?");
            args.add(carrier);
        }
        if (maxPrice != null) {
            sql.append(" AND price <= ?");
            args.add(maxPrice);
        }
        sql.append(" ORDER BY price");
        return jdbc.query(sql.toString(), OFFER_MAPPER, args.toArray());
    }

    public Optional<Offer> findById(long id) {
        return jdbc.query(SELECT_OFFER + " WHERE id = ?", OFFER_MAPPER, id).stream().findFirst();
    }

    public Offer save(Offer offer) {
        Number id = insert.executeAndReturnKey(Map.of(
                "origin", offer.origin(),
                "destination", offer.destination(),
                "carrier", offer.carrier(),
                "price", offer.price(),
                "departure", offer.departure()));
        return new Offer(id.longValue(), offer.origin(), offer.destination(), offer.carrier(),
                offer.price(), offer.departure());
    }
}
