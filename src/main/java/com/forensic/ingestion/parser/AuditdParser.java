package com.forensic.ingestion.parser;

import com.forensic.ingestion.domain.NormalizedEvent;
import com.forensic.ingestion.domain.RawLogPayload.LogSource;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@Component
public class AuditdParser implements LogParser {

    @Override
    public boolean supports(LogSource source) {
        return source == LogSource.AUDITD;
    }

    @Override
    public NormalizedEvent parse(String rawLog) {
        // Mock parsing logic for Auditd
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("raw", rawLog);
        metadata.put("type", "SYSCALL");
        
        return NormalizedEvent.builder()
                .timestamp(Instant.now())
                .subject("user_id=1000")
                .relationship("ACCESSED")
                .object("/etc/passwd")
                .metadata(metadata)
                .build();
    }
}
