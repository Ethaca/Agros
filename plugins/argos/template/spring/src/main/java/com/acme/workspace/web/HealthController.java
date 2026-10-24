package com.acme.workspace.web;

import java.util.Map;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/** Readiness probe used by the load balancer. Anonymous; touches the database. */
@RestController
public class HealthController {

    private final JdbcTemplate jdbc;

    public HealthController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @GetMapping("/healthz")
    public Map<String, String> health() {
        jdbc.queryForObject("select 1", Integer.class);
        return Map.of("status", "ok");
    }
}
