package com.forensic.ingestion.domain;

import lombok.Builder;
import lombok.Data;

import java.time.Instant;
import java.util.Map;

@Data
@Builder
public class NormalizedEvent {
    private Instant timestamp;
    private String subject;
    private String relationship;
    private String object;
    private Map<String, Object> metadata;
}
