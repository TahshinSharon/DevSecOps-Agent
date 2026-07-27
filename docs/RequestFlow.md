# Request Flow

1. User logs in and receives JWT.
2. User starts an inspection.
3. Backend creates an inspection record with `running` status.
4. Frontend opens WebSocket for that inspection ID.
5. Backend scans Docker daemon.
6. Backend analyzes results.
7. Backend saves final JSON report.
8. Frontend opens report page.
