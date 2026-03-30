from __future__ import annotations

from urllib.parse import quote


def lua_string_literal(value: str) -> str:
    escaped = (
        value.replace("\\", "\\\\")
        .replace("\r", "\\r")
        .replace("\n", "\\n")
        .replace("'", "\\'")
    )
    return f"'{escaped}'"


def firestore_document_url(project_id: str, collection: str, script_id: str) -> str:
    return (
        "https://firestore.googleapis.com/v1/projects/"
        f"{quote(project_id, safe='')}/databases/(default)/documents/"
        f"{quote(collection, safe='')}/{quote(script_id, safe='')}"
    )


def shared_key_reader_lua() -> str:
    return """local function readScriptKey()
    if type(script_key) == "string" and script_key ~= "" then
        return script_key
    end

    local env = getgenv and getgenv() or nil
    if env and type(env.script_key) == "string" and env.script_key ~= "" then
        return env.script_key
    end

    if _G and type(_G.script_key) == "string" and _G.script_key ~= "" then
        return _G.script_key
    end

    if shared and type(shared.script_key) == "string" and shared.script_key ~= "" then
        return shared.script_key
    end

    return nil
end
"""


def build_firestore_fallback_loader_source(script_key: str, project_id: str, collection: str, script_id: str) -> str:
    document_url = lua_string_literal(firestore_document_url(project_id, collection, script_id))
    expected_key = lua_string_literal(script_key)
    return (
        shared_key_reader_lua()
        + f"""
local key = readScriptKey()
if key ~= {expected_key} then
    error("Invalid script_key")
end

local HttpService = game:GetService("HttpService")
local document = HttpService:JSONDecode(game:HttpGet({document_url}))
local fields = document and document.fields or nil
local rawField = fields and fields.raw_script or nil
local scriptSource = rawField and rawField.stringValue or nil

if type(scriptSource) ~= "string" or scriptSource == "" then
    error("Missing script")
end

loadstring(scriptSource)()
"""
    )


def build_final_snippet(
    script_key: str,
    primary_loader_url: str,
    project_id: str,
    collection: str,
    script_id: str,
) -> str:
    expected_key = lua_string_literal(script_key)
    return f"""script_key = {expected_key}
loadstring(game:HttpGet({lua_string_literal(primary_loader_url)}))()
"""
