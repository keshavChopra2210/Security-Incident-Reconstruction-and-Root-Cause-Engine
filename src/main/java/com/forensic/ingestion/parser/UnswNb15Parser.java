package com.forensic.ingestion.parser;

import com.forensic.ingestion.domain.NormalizedEvent;
import com.forensic.ingestion.domain.RawLogPayload;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@Component
public class UnswNb15Parser implements LogParser {

    @Override
    public boolean supports(RawLogPayload.LogSource source) {
        return source == RawLogPayload.LogSource.UNSW_NB15;
    }

    @Override
    public NormalizedEvent parse(String rawLog) {
        String[] parts = rawLog.split(",");

        if (parts.length < 49) {
            throw new IllegalArgumentException("Invalid UNSW-NB15 CSV format");
        }

        String srcIp = parts[0];
        String sport = parts[1];
        String dstIp = parts[2];
        String dport = parts[3];
        String proto = parts[4];
        String state = parts[5];
        String attackCat = parts[47].trim();
        String label = parts[48].trim();

        // If it's an attack, make the relationship the attack category (e.g. EXPLOIT)
        // If it's normal traffic, make it the protocol (e.g. NORMAL_UDP)
        String relationship;
        if ("1".equals(label)) {
            relationship = attackCat.isEmpty() ? "ATTACK_GENERIC" : "ATTACK_" + attackCat.toUpperCase().replaceAll("[^A-Z0-9_]", "_");
        } else {
            relationship = "NORMAL_" + proto.toUpperCase().replaceAll("[^A-Z0-9_]", "_");
        }

        Map<String, Object> metadata = new HashMap<>();
        metadata.put("sport", sport);
        metadata.put("dport", dport);
        metadata.put("state", state);
        metadata.put("label", label);

        return NormalizedEvent.builder()
                .timestamp(Instant.now())
                .subject(srcIp)
                .object(dstIp)
                .relationship(relationship)
                .metadata(metadata)
                .build();
    }
}
