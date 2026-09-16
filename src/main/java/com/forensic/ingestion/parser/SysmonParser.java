package com.forensic.ingestion.parser;

import com.forensic.ingestion.domain.NormalizedEvent;
import com.forensic.ingestion.domain.RawLogPayload.LogSource;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@Component
public class SysmonParser implements LogParser {

    @Override
    public boolean supports(LogSource source) {
        return source == LogSource.SYSMON;
    }

    @Override
    public NormalizedEvent parse(String rawLog) {
        // Mock parsing logic for Sysmon
        // In reality, we would parse XML/JSON using Jackson or JAXB
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("raw", rawLog);
        metadata.put("eventId", 1);
        
        return NormalizedEvent.builder()
                .timestamp(Instant.now())
                .subject("C:\\Windows\\System32\\cmd.exe")
                .relationship("EXECUTED")
                .object("C:\\Windows\\System32\\calc.exe")
                .metadata(metadata)
                .build();
    }
}
