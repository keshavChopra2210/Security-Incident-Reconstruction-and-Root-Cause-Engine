package com.forensic.ingestion.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.forensic.ingestion.domain.NormalizedEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HashMap;

import static org.junit.jupiter.api.Assertions.*;

class MerkleTreeServiceTest {

    private MerkleTreeService service;

    @BeforeEach
    void setUp() throws NoSuchAlgorithmException {
        ObjectMapper mapper = new ObjectMapper();
        mapper.registerModule(new JavaTimeModule());
        service = new MerkleTreeService(mapper);
    }

    @Test
    void testAppendAndRootHash() {
        NormalizedEvent event1 = NormalizedEvent.builder()
                .timestamp(Instant.now())
                .subject("User1")
                .relationship("LOGIN")
                .object("System")
                .metadata(new HashMap<>())
                .build();

        NormalizedEvent event2 = NormalizedEvent.builder()
                .timestamp(Instant.now())
                .subject("User2")
                .relationship("LOGOUT")
                .object("System")
                .metadata(new HashMap<>())
                .build();

        String hash1 = service.appendEvent(event1);
        assertNotNull(hash1);
        String root1 = service.getRootHash();
        assertEquals(hash1, root1); // 1 node -> root is the node itself

        String hash2 = service.appendEvent(event2);
        assertNotNull(hash2);
        String root2 = service.getRootHash();
        assertNotEquals(root1, root2); // Root should change
        assertNotEquals(hash2, root2); // 2 nodes -> root is hash(node1 + node2)
    }
}
