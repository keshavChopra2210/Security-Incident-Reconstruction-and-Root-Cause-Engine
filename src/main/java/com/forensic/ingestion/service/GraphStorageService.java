package com.forensic.ingestion.service;

import com.forensic.ingestion.domain.NormalizedEvent;
import org.springframework.data.neo4j.core.Neo4jClient;
import org.springframework.stereotype.Service;

@Service
public class GraphStorageService {

    private final Neo4jClient neo4jClient;

    public GraphStorageService(Neo4jClient neo4jClient) {
        this.neo4jClient = neo4jClient;
    }

    public void saveEvent(NormalizedEvent event, String eventHash) {
        // Sanitize relationship to prevent Cypher injection (must be uppercase alphanumeric)
        String relType = event.getRelationship().toUpperCase().replaceAll("[^A-Z0-9_]", "_");

        String cypher = String.format(
            "MERGE (s:Entity {name: $subject}) " +
            "MERGE (o:Entity {name: $object}) " +
            "CREATE (s)-[r:%s {timestamp: $timestamp, eventHash: $eventHash}]->(o)", relType);

        neo4jClient.query(cypher)
                .bind(event.getSubject()).to("subject")
                .bind(event.getObject()).to("object")
                .bind(event.getTimestamp().toString()).to("timestamp")
                .bind(eventHash).to("eventHash")
                .run();
    }
}
