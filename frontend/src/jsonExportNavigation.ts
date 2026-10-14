export type ExportMode = "manual" | "group" | "paste";

export function exportMode(params: URLSearchParams): ExportMode {
  if (params.get("source") === "paste" || params.has("external_batch_id")) return "paste";
  return params.get("source") === "group" || params.has("group_id") ? "group" : "manual";
}

export function exportTaskParams(source: ExportMode, id: string) {
  return new URLSearchParams({ source, [source === "paste" ? "external_batch_id" : "batch_id"]: id });
}

// Only navigation IDs are retained, scoped to the signed-in user. Never persist
// pasted account text, results, URLs, passwords or challenge contents here.
export function rememberedExport(params: URLSearchParams): string | null {
  const source = exportMode(params), id = params.get(source === "paste" ? "external_batch_id" : "batch_id");
  return id && /^[a-zA-Z0-9_-]{1,80}$/.test(id) ? JSON.stringify({ source, id }) : null;
}

export function restoreExport(raw: string | null): URLSearchParams | null {
  try {
    const value = JSON.parse(raw || "null");
    return value && ["manual", "group", "paste"].includes(value.source) && typeof value.id === "string" && /^[a-zA-Z0-9_-]{1,80}$/.test(value.id)
      ? exportTaskParams(value.source, value.id) : null;
  } catch { return null; }
}
