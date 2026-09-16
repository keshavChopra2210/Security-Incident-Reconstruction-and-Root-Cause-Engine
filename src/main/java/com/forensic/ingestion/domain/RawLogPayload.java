package com.forensic.ingestion.domain;

import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class RawLogPayload {
    private LogSource source;
    private String rawLog;

    public enum LogSource {
        SYSMON, AUDITD
    }
}
