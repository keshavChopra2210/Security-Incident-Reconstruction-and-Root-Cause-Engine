package com.forensic.ingestion.parser;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.forensic.ingestion.domain.NormalizedEvent;
import com.forensic.ingestion.domain.RawLogPayload.LogSource;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/**
 * TheiaParser
 * ===========
 * Parses DARPA TC Engagement 5 (Theia) CDM20 telemetry records from their
 * JSON representation (as produced by {@code data.py --json}) into the
 * shared {@link NormalizedEvent} model.
 *
 * <p>The expected JSON envelope shape is:
 * <pre>
 * {
 *   "record_type": "RECORD_EVENT" | "RECORD_SUBJECT" | "RECORD_FILE_OBJECT"
 *                | "RECORD_NET_FLOW_OBJECT" | "RECORD_HOST" | "RECORD_PRINCIPAL" | ...,
 *   "cdm_version":  20,
 *   "session":      &lt;int&gt;,
 *   "source":       "SOURCE_LINUX_AUDIT_TRACE" | ...,
 *   "host_id":      "&lt;uuid-hex&gt;",
 *   "datum":        { ... record-type-specific fields ... }
 * }
 * </pre>
 *
 * <h3>NormalizedEvent mapping strategy</h3>
 * <ul>
 *   <li><b>subject</b>      – the acting entity (process UUID for events, host name for host records)</li>
 *   <li><b>relationship</b> – CDM event type (e.g. {@code EVENT_WRITE}) or a semantic label
 *       ({@code IS_SUBJECT}, {@code IS_FILE}, {@code IS_NETFLOW}, {@code IS_HOST}, {@code IS_PRINCIPAL})</li>
 *   <li><b>object</b>       – the acted-upon entity (predicate object UUID, file path, remote IP:port, etc.)</li>
 *   <li><b>metadata</b>     – a flat map of all remaining useful CDM fields</li>
 * </ul>
 */
@Component
public class TheiaParser implements LogParser {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    // ── Record type constants ────────────────────────────────────────────────

    private static final String RT_EVENT    = "RECORD_EVENT";
    private static final String RT_SUBJECT  = "RECORD_SUBJECT";
    private static final String RT_FILE     = "RECORD_FILE_OBJECT";
    private static final String RT_NETFLOW  = "RECORD_NET_FLOW_OBJECT";
    private static final String RT_HOST     = "RECORD_HOST";
    private static final String RT_PRINCIPAL = "RECORD_PRINCIPAL";
    private static final String RT_IPC      = "RECORD_IPC_OBJECT";
    private static final String RT_MEMORY   = "RECORD_MEMORY_OBJECT";
    private static final String RT_SRCSINK  = "RECORD_SRCSINK_OBJECT";
    private static final String RT_REGKEY   = "RECORD_REGISTRY_KEY_OBJECT";

    // ── LogParser contract ───────────────────────────────────────────────────

    @Override
    public boolean supports(LogSource source) {
        return source == LogSource.THEIA;
    }

    /**
     * Entry point. {@code rawLog} must be a valid JSON string matching the
     * CDM20 envelope produced by {@code data.py --json}.
     *
     * @param rawLog JSON CDM20 record string
     * @return a {@link NormalizedEvent} ready for Merkle-tree hashing and graph storage
     * @throws TheiaParseException if the JSON is malformed or the record type is unsupported
     */
    @Override
    public NormalizedEvent parse(String rawLog) {
        JsonNode root;
        try {
            root = MAPPER.readTree(rawLog);
        } catch (Exception e) {
            throw new TheiaParseException("Invalid JSON input for Theia parser: " + e.getMessage(), e);
        }

        String recordType = textOrEmpty(root, "record_type");
        JsonNode datum = root.path("datum");

        // Build shared envelope metadata
        Map<String, Object> meta = new HashMap<>();
        meta.put("record_type", recordType);
        meta.put("cdm_version", nodeToString(root.path("cdm_version")));
        meta.put("session",     nodeToString(root.path("session")));
        meta.put("source",      textOrEmpty(root, "source"));
        meta.put("host_id",     textOrEmpty(root, "host_id"));
        meta.put("raw",         rawLog);

        return switch (recordType) {
            case RT_EVENT     -> parseEvent(datum, meta);
            case RT_SUBJECT   -> parseSubject(datum, meta);
            case RT_FILE      -> parseFileObject(datum, meta);
            case RT_NETFLOW   -> parseNetFlowObject(datum, meta);
            case RT_HOST      -> parseHost(datum, meta);
            case RT_PRINCIPAL -> parsePrincipal(datum, meta);
            case RT_IPC       -> parseIpcObject(datum, meta);
            case RT_MEMORY    -> parseMemoryObject(datum, meta);
            case RT_SRCSINK   -> parseSrcSinkObject(datum, meta);
            case RT_REGKEY    -> parseRegistryKeyObject(datum, meta);
            default           -> parseGeneric(recordType, datum, meta);
        };
    }

    // ── Per-type parsers ─────────────────────────────────────────────────────

    /**
     * RECORD_EVENT — a provenance event edge between two entities.
     *
     * <p>subject      = subject process UUID
     * <p>relationship = CDM event type (e.g. {@code EVENT_WRITE})
     * <p>object       = predicate object UUID (or human-readable path when available)
     */
    private NormalizedEvent parseEvent(JsonNode d, Map<String, Object> meta) {
        String eventType   = textOrEmpty(d, "type");
        String subjectUuid = textOrEmpty(d, "subject");
        String objectUuid  = textOrEmpty(d, "predicateObject");
        String objectPath  = textOrEmpty(d, "predicateObjectPath");
        String object      = objectPath.isEmpty() ? objectUuid : objectPath;

        Instant timestamp = parseTimestamp(d, "timestampNanos", "timestampNanos_utc");

        putIfPresent(meta, d, "uuid",             "event_uuid");
        putIfPresent(meta, d, "sequence",         "sequence");
        putIfPresent(meta, d, "threadId",         "thread_id");
        putIfPresent(meta, d, "names",            "syscalls");
        putIfPresent(meta, d, "size",             "size_bytes");
        putIfPresent(meta, d, "location",         "location");
        putIfPresent(meta, d, "predicateObject2", "predicate_object2");
        putIfPresent(meta, d, "properties",       "properties");

        return NormalizedEvent.builder()
                .timestamp(timestamp)
                .subject(subjectUuid.isEmpty() ? "unknown-subject" : subjectUuid)
                .relationship(eventType.isEmpty() ? "EVENT_UNKNOWN" : eventType)
                .object(object.isEmpty() ? "unknown-object" : object)
                .metadata(meta)
                .build();
    }

    /**
     * RECORD_SUBJECT — a process/thread entity definition.
     *
     * <p>subject      = subject UUID
     * <p>relationship = {@code IS_SUBJECT}
     * <p>object       = command line, or "pid=&lt;PID&gt;" if cmdLine absent
     */
    private NormalizedEvent parseSubject(JsonNode d, Map<String, Object> meta) {
        String uuid    = textOrEmpty(d, "uuid");
        String cmdLine = textOrEmpty(d, "cmdLine");
        String pid     = nodeToString(d.path("pid"));

        Instant timestamp = parseTimestamp(d, "startTimestampNanos", "startTimestampNanos_utc");

        putIfPresent(meta, d, "type",           "subject_type");
        putIfPresent(meta, d, "pid",            "pid");
        putIfPresent(meta, d, "unitId",         "unit_id");
        putIfPresent(meta, d, "parentSubject",  "parent_subject_uuid");
        putIfPresent(meta, d, "localPrincipal", "local_principal_uuid");
        putIfPresent(meta, d, "properties",     "properties");

        String obj = cmdLine.isEmpty()
                ? (pid.isEmpty() ? uuid : "pid=" + pid)
                : cmdLine;

        return NormalizedEvent.builder()
                .timestamp(timestamp)
                .subject(uuid.isEmpty() ? "unknown-subject" : uuid)
                .relationship("IS_SUBJECT")
                .object(obj)
                .metadata(meta)
                .build();
    }

    /**
     * RECORD_FILE_OBJECT — a file entity definition.
     *
     * <p>subject      = file UUID
     * <p>relationship = {@code IS_FILE}
     * <p>object       = file path (the {@code url} field in CDM)
     */
    private NormalizedEvent parseFileObject(JsonNode d, Map<String, Object> meta) {
        String uuid = textOrEmpty(d, "uuid");
        String url  = textOrEmpty(d, "url");

        putIfPresent(meta, d, "type",           "file_type");
        putIfPresent(meta, d, "fileDescriptor", "file_descriptor");
        putIfPresent(meta, d, "localPrincipal", "owner_uuid");
        putIfPresent(meta, d, "size",           "size_bytes");
        putIfPresent(meta, d, "properties",     "properties");

        return NormalizedEvent.builder()
                .timestamp(Instant.EPOCH)
                .subject(uuid.isEmpty() ? "unknown-file" : uuid)
                .relationship("IS_FILE")
                .object(url.isEmpty() ? uuid : url)
                .metadata(meta)
                .build();
    }

    /**
     * RECORD_NET_FLOW_OBJECT — a network socket entity.
     *
     * <p>subject      = netflow UUID
     * <p>relationship = {@code IS_NETFLOW}
     * <p>object       = "remoteAddress:remotePort"
     */
    private NormalizedEvent parseNetFlowObject(JsonNode d, Map<String, Object> meta) {
        String uuid       = textOrEmpty(d, "uuid");
        String localAddr  = textOrEmpty(d, "localAddress");
        String localPort  = nodeToString(d.path("localPort"));
        String remoteAddr = textOrEmpty(d, "remoteAddress");
        String remotePort = nodeToString(d.path("remotePort"));

        meta.put("local_endpoint",  localAddr + ":" + localPort);
        meta.put("remote_endpoint", remoteAddr + ":" + remotePort);
        meta.put("ip_protocol",     nodeToString(d.path("ipProtocol")));
        putIfPresent(meta, d, "properties", "properties");

        String endpoint = remoteAddr.isEmpty() ? uuid : remoteAddr + ":" + remotePort;

        return NormalizedEvent.builder()
                .timestamp(Instant.EPOCH)
                .subject(uuid.isEmpty() ? "unknown-netflow" : uuid)
                .relationship("IS_NETFLOW")
                .object(endpoint)
                .metadata(meta)
                .build();
    }

    /**
     * RECORD_HOST — host/machine entity.
     *
     * <p>subject      = host UUID
     * <p>relationship = {@code IS_HOST}
     * <p>object       = hostname
     */
    private NormalizedEvent parseHost(JsonNode d, Map<String, Object> meta) {
        String uuid     = textOrEmpty(d, "uuid");
        String hostname = textOrEmpty(d, "hostName");

        meta.put("os_details", textOrEmpty(d, "osDetails"));
        meta.put("host_type",  textOrEmpty(d, "hostType"));
        putIfPresent(meta, d, "properties", "properties");

        return NormalizedEvent.builder()
                .timestamp(Instant.EPOCH)
                .subject(uuid.isEmpty() ? "unknown-host" : uuid)
                .relationship("IS_HOST")
                .object(hostname.isEmpty() ? uuid : hostname)
                .metadata(meta)
                .build();
    }

    /**
     * RECORD_PRINCIPAL — a user/group security principal.
     *
     * <p>subject      = principal UUID
     * <p>relationship = {@code IS_PRINCIPAL}
     * <p>object       = userId
     */
    private NormalizedEvent parsePrincipal(JsonNode d, Map<String, Object> meta) {
        String uuid   = textOrEmpty(d, "uuid");
        String userId = textOrEmpty(d, "userId");

        meta.put("group_ids",      nodeToString(d.path("groupIds")));
        meta.put("principal_type", textOrEmpty(d, "type"));
        putIfPresent(meta, d, "properties", "properties");

        return NormalizedEvent.builder()
                .timestamp(Instant.EPOCH)
                .subject(uuid.isEmpty() ? "unknown-principal" : uuid)
                .relationship("IS_PRINCIPAL")
                .object(userId.isEmpty() ? uuid : userId)
                .metadata(meta)
                .build();
    }

    /**
     * RECORD_IPC_OBJECT — inter-process communication object (pipe, socket pair, etc.)
     */
    private NormalizedEvent parseIpcObject(JsonNode d, Map<String, Object> meta) {
        String uuid = textOrEmpty(d, "uuid");
        meta.put("ipc_type", textOrEmpty(d, "type"));
        putIfPresent(meta, d, "properties", "properties");

        return NormalizedEvent.builder()
                .timestamp(Instant.EPOCH)
                .subject(uuid.isEmpty() ? "unknown-ipc" : uuid)
                .relationship("IS_IPC")
                .object(uuid)
                .metadata(meta)
                .build();
    }

    /**
     * RECORD_MEMORY_OBJECT — anonymous memory region.
     */
    private NormalizedEvent parseMemoryObject(JsonNode d, Map<String, Object> meta) {
        String uuid    = textOrEmpty(d, "uuid");
        String memAddr = nodeToString(d.path("memoryAddress"));
        String size    = nodeToString(d.path("size"));

        meta.put("memory_address", memAddr);
        meta.put("size_bytes",     size);
        putIfPresent(meta, d, "properties", "properties");

        String addrLabel = memAddr.isEmpty() ? uuid : "0x" + memAddr;

        return NormalizedEvent.builder()
                .timestamp(Instant.EPOCH)
                .subject(uuid.isEmpty() ? "unknown-memory" : uuid)
                .relationship("IS_MEMORY")
                .object(addrLabel)
                .metadata(meta)
                .build();
    }

    /**
     * RECORD_SRCSINK_OBJECT — source/sink object (stdin, stdout, device, etc.)
     */
    private NormalizedEvent parseSrcSinkObject(JsonNode d, Map<String, Object> meta) {
        String uuid     = textOrEmpty(d, "uuid");
        String sinkType = textOrEmpty(d, "type");
        putIfPresent(meta, d, "properties", "properties");

        return NormalizedEvent.builder()
                .timestamp(Instant.EPOCH)
                .subject(uuid.isEmpty() ? "unknown-srcsink" : uuid)
                .relationship("IS_SRCSINK")
                .object(sinkType.isEmpty() ? uuid : sinkType)
                .metadata(meta)
                .build();
    }

    /**
     * RECORD_REGISTRY_KEY_OBJECT — Windows registry key (where present in the dataset).
     */
    private NormalizedEvent parseRegistryKeyObject(JsonNode d, Map<String, Object> meta) {
        String uuid = textOrEmpty(d, "uuid");
        String key  = textOrEmpty(d, "key");
        putIfPresent(meta, d, "properties", "properties");

        return NormalizedEvent.builder()
                .timestamp(Instant.EPOCH)
                .subject(uuid.isEmpty() ? "unknown-regkey" : uuid)
                .relationship("IS_REGKEY")
                .object(key.isEmpty() ? uuid : key)
                .metadata(meta)
                .build();
    }

    /**
     * Fallback for any CDM record type not explicitly handled above.
     */
    private NormalizedEvent parseGeneric(String recordType, JsonNode d, Map<String, Object> meta) {
        String uuid = textOrEmpty(d, "uuid");
        meta.put("datum_json", d.toString());

        return NormalizedEvent.builder()
                .timestamp(Instant.EPOCH)
                .subject(uuid.isEmpty() ? "unknown" : uuid)
                .relationship("CDM_" + recordType.replace("RECORD_", ""))
                .object(uuid.isEmpty() ? recordType : uuid)
                .metadata(meta)
                .build();
    }

    // ── Timestamp helpers ────────────────────────────────────────────────────

    /**
     * Parses a nanosecond epoch field from the datum node.
     * Falls back to the human-readable UTC sibling field, then to {@link Instant#EPOCH}.
     */
    private Instant parseTimestamp(JsonNode node, String nanosField, String utcField) {
        JsonNode nanosNode = node.path(nanosField);
        if (!nanosNode.isMissingNode() && nanosNode.isNumber()) {
            long nanos = nanosNode.longValue();
            if (nanos > 0) {
                try {
                    return Instant.ofEpochSecond(nanos / 1_000_000_000L,
                                                 (int) (nanos % 1_000_000_000L));
                } catch (Exception ignored) { /* fall through */ }
            }
        }
        String utcStr = textOrEmpty(node, utcField);
        if (!utcStr.isEmpty() && !utcStr.equals("N/A")) {
            try {
                // data.py format: "2019-04-10 08:12:34.123456 UTC" -> ISO-8601
                return Instant.parse(utcStr.replace(" UTC", "Z").replace(" ", "T"));
            } catch (Exception ignored) { /* fall through */ }
        }
        return Instant.EPOCH;
    }

    // ── JSON utility helpers ─────────────────────────────────────────────────

    private static String textOrEmpty(JsonNode node, String field) {
        JsonNode n = node.path(field);
        return (n.isMissingNode() || n.isNull()) ? "" : n.asText("");
    }

    private static String nodeToString(JsonNode node) {
        return (node.isMissingNode() || node.isNull()) ? "" : node.toString();
    }

    /** Copies a datum field into the metadata map if it is present and non-null. */
    private static void putIfPresent(Map<String, Object> meta, JsonNode node,
                                     String field, String metaKey) {
        JsonNode n = node.path(field);
        if (!n.isMissingNode() && !n.isNull()) {
            meta.put(metaKey, n.isTextual() ? n.asText() : n.toString());
        }
    }

    // ── Custom exception ─────────────────────────────────────────────────────

    /** Thrown when a raw Theia JSON record cannot be parsed. */
    public static class TheiaParseException extends RuntimeException {
        public TheiaParseException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
