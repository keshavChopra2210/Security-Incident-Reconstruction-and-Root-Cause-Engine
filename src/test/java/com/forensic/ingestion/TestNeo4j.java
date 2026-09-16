package com.forensic.ingestion;

import org.junit.jupiter.api.Test;
import org.neo4j.driver.AuthTokens;
import org.neo4j.driver.Driver;
import org.neo4j.driver.GraphDatabase;

public class TestNeo4j {
    @Test
    public void testAuth() {
        String uri = "neo4j+s://c8b83293.databases.neo4j.io";
        String password = "v-dqoNTMHSPPKmQQRbWxqt9iHrgd0P1a1nUvOXJPCRQ";
        
        System.out.println("Testing with username 'neo4j'");
        try (Driver driver = GraphDatabase.driver(uri, AuthTokens.basic("neo4j", password))) {
            driver.verifyConnectivity();
            System.out.println("SUCCESS with 'neo4j'");
            return;
        } catch (Exception e) {
            System.out.println("FAILED with 'neo4j': " + e.getMessage());
        }

        System.out.println("Testing with username 'c8b83293'");
        try (Driver driver = GraphDatabase.driver(uri, AuthTokens.basic("c8b83293", password))) {
            driver.verifyConnectivity();
            System.out.println("SUCCESS with 'c8b83293'");
        } catch (Exception e) {
            System.out.println("FAILED with 'c8b83293': " + e.getMessage());
        }
    }
}
