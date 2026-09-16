package com.forensic.ingestion.parser;

import com.forensic.ingestion.domain.NormalizedEvent;
import com.forensic.ingestion.domain.RawLogPayload.LogSource;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ParsersTest {

    @Test
    void testSysmonParser() {
        SysmonParser parser = new SysmonParser();
        assertTrue(parser.supports(LogSource.SYSMON));
        assertFalse(parser.supports(LogSource.AUDITD));

        NormalizedEvent event = parser.parse("mock raw log");
        assertNotNull(event);
        assertEquals("C:\\Windows\\System32\\cmd.exe", event.getSubject());
        assertEquals("EXECUTED", event.getRelationship());
        assertEquals("C:\\Windows\\System32\\calc.exe", event.getObject());
    }

    @Test
    void testAuditdParser() {
        AuditdParser parser = new AuditdParser();
        assertTrue(parser.supports(LogSource.AUDITD));
        assertFalse(parser.supports(LogSource.SYSMON));

        NormalizedEvent event = parser.parse("mock raw log");
        assertNotNull(event);
        assertEquals("user_id=1000", event.getSubject());
        assertEquals("ACCESSED", event.getRelationship());
        assertEquals("/etc/passwd", event.getObject());
    }
}
