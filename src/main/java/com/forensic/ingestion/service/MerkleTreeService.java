package com.forensic.ingestion.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.forensic.ingestion.domain.NormalizedEvent;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

@Service
public class MerkleTreeService {

    private final List<String> leaves = new ArrayList<>();
    private final ObjectMapper objectMapper;
    private final MessageDigest digest;

    public MerkleTreeService(ObjectMapper objectMapper) throws NoSuchAlgorithmException {
        this.objectMapper = objectMapper;
        this.digest = MessageDigest.getInstance("SHA-256");
    }

    public synchronized String appendEvent(NormalizedEvent event) {
        try {
            String json = objectMapper.writeValueAsString(event);
            String hash = hash(json);
            leaves.add(hash);
            return hash;
        } catch (Exception e) {
            throw new RuntimeException("Failed to hash event", e);
        }
    }

    public synchronized String getRootHash() {
        if (leaves.isEmpty()) {
            return null;
        }
        return computeRoot(new ArrayList<>(leaves));
    }

    private String computeRoot(List<String> currentLevel) {
        if (currentLevel.size() == 1) {
            return currentLevel.get(0);
        }

        List<String> nextLevel = new ArrayList<>();
        for (int i = 0; i < currentLevel.size(); i += 2) {
            String left = currentLevel.get(i);
            String right = (i + 1 < currentLevel.size()) ? currentLevel.get(i + 1) : left; // Duplicate last if odd
            nextLevel.add(hash(left + right));
        }

        return computeRoot(nextLevel);
    }

    private String hash(String input) {
        byte[] encodedHash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
        return bytesToHex(encodedHash);
    }

    private String bytesToHex(byte[] hash) {
        StringBuilder hexString = new StringBuilder(2 * hash.length);
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
}
