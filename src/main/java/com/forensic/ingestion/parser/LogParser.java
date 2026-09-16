package com.forensic.ingestion.parser;

import com.forensic.ingestion.domain.NormalizedEvent;
import com.forensic.ingestion.domain.RawLogPayload.LogSource;

public interface LogParser {
    boolean supports(LogSource source);
    NormalizedEvent parse(String rawLog);
}
