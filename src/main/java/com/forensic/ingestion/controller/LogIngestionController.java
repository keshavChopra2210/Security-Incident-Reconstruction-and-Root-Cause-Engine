package com.forensic.ingestion.controller;

import com.forensic.ingestion.domain.IngestionResponse;
import com.forensic.ingestion.domain.NormalizedEvent;
import com.forensic.ingestion.domain.RawLogPayload;
import com.forensic.ingestion.parser.LogParser;
import com.forensic.ingestion.service.GraphStorageService;
import com.forensic.ingestion.service.MerkleTreeService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/v1/logs")
public class LogIngestionController {

    private final List<LogParser> parsers;
    private final MerkleTreeService merkleTreeService;
    private final GraphStorageService graphStorageService;

    public LogIngestionController(List<LogParser> parsers, MerkleTreeService merkleTreeService, GraphStorageService graphStorageService) {
        this.parsers = parsers;
        this.merkleTreeService = merkleTreeService;
        this.graphStorageService = graphStorageService;
    }

    @PostMapping("/ingest")
    public ResponseEntity<IngestionResponse> ingestLog(@RequestBody RawLogPayload payload) {
        LogParser parser = parsers.stream()
                .filter(p -> p.supports(payload.getSource()))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Unsupported log source: " + payload.getSource()));

        NormalizedEvent event = parser.parse(payload.getRawLog());
        
        String leafHash = merkleTreeService.appendEvent(event);
        String rootHash = merkleTreeService.getRootHash();

        // Save to Neo4j Graph Database
        try {
            graphStorageService.saveEvent(event, leafHash);
        } catch (Exception e) {
            // Log but don't fail ingestion for Phase 2 demo purposes
            System.err.println("Failed to save to Neo4j: " + e.getMessage());
        }

        IngestionResponse response = IngestionResponse.builder()
                .normalizedEvent(event)
                .eventHash(leafHash)
                .merkleRoot(rootHash)
                .build();

        return ResponseEntity.ok(response);
    }
}
