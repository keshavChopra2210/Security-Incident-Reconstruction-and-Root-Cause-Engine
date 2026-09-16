package com.forensic.ingestion.domain;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class IngestionResponse {
    private NormalizedEvent normalizedEvent;
    private String eventHash;
    private String merkleRoot;
}
