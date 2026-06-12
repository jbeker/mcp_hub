-- Cached snapshot of what a backend advertises to MCP clients (serverInfo,
-- protocol version, capabilities, instructions, tool/prompt/resource lists),
-- captured by Test connection / Refresh capabilities. JSON-serialized
-- CapabilitiesSnapshot; NULL until the backend has been probed successfully
-- at least once.
ALTER TABLE user_server_instances ADD COLUMN capabilities_json TEXT;
