/**
 * API client for Authorization Debugger backend.
 * Integrates with FastAPI endpoints defined in backend/app/main.py:
 * - GET  /health
 * - GET  /api/v1/traces
 * - GET  /api/v1/traces/{trace_id}
 * - GET  /api/v1/spans?limit=...
 */

import type { SpanRecord, TraceSummary } from './types.ts';

/**
 * Default API base URL for local development:
 * Empty string indicates same-origin relative requests handled by Vite's dev proxy
 * (configured in vite.config.ts to forward /api and /health to http://localhost:8000).
 */
export const DEFAULT_API_BASE_URL = '';

export const FRIENDLY_ERROR_DETAIL =
  'The trace service may be unavailable. Check that the backend is running, then try again.';

export function getInitialApiBaseUrl(): string {
  if (
    typeof import.meta !== 'undefined' &&
    import.meta.env?.VITE_API_BASE_URL !== undefined &&
    import.meta.env?.VITE_API_BASE_URL !== ''
  ) {
    return String(import.meta.env.VITE_API_BASE_URL).replace(/\/+$/, '');
  }
  return DEFAULT_API_BASE_URL;
}

/**
 * Build the full request URL for a given endpoint and optional base URL override.
 */
export function buildApiUrl(endpoint: string, baseUrl?: string): string {
  const root = (baseUrl !== undefined ? baseUrl : getInitialApiBaseUrl()).replace(/\/+$/, '');
  return `${root}${endpoint}`;
}

export class ApiError extends Error {
  public status: number;
  public statusText: string;
  public details?: unknown;

  constructor(message: string, status: number, statusText: string, details?: unknown) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.statusText = statusText;
    this.details = details;
  }
}

async function request<T>(endpoint: string, baseUrl?: string): Promise<T> {
  const url = buildApiUrl(endpoint, baseUrl);

  let response: Response;
  try {
    response = await fetch(url, {
      method: 'GET',
      headers: {
        Accept: 'application/json',
      },
    });
  } catch (err) {
    // Keep technical details in the console for debugging
    console.error(`[API Network Error] Failed to connect to ${url}:`, err);
    throw new ApiError(
      FRIENDLY_ERROR_DETAIL,
      0,
      'NetworkError',
      err instanceof Error ? err.message : String(err)
    );
  }

  // Read response body text exactly ONCE
  let rawBody = '';
  try {
    rawBody = await response.text();
  } catch (readErr) {
    console.error(`[API Body Read Error] Failed to read response stream from ${url}:`, readErr);
  }

  if (!response.ok) {
    let parsedDetail: unknown = rawBody;
    if (rawBody) {
      try {
        const errJson = JSON.parse(rawBody);
        parsedDetail = errJson.detail || errJson;
      } catch {
        // rawBody is string content
      }
    }

    // Keep technical details in the console for debugging
    console.error(
      `[API Error Response] ${response.status} ${response.statusText} from ${url}:`,
      parsedDetail
    );

    throw new ApiError(
      FRIENDLY_ERROR_DETAIL,
      response.status,
      response.statusText,
      parsedDetail
    );
  }

  try {
    return JSON.parse(rawBody) as T;
  } catch (parseErr) {
    // Keep technical details in the console for debugging
    console.error(
      `[API JSON Parse Error] Failed to parse response from ${url}:`,
      rawBody,
      parseErr
    );
    throw new ApiError(
      FRIENDLY_ERROR_DETAIL,
      response.status,
      'ParseError',
      parseErr instanceof Error ? parseErr.message : String(parseErr)
    );
  }
}

/**
 * Check backend health status: GET /health
 */
export async function fetchHealth(baseUrl?: string): Promise<{ status: string }> {
  return request<{ status: string }>('/health', baseUrl);
}

/**
 * List all available trace summaries: GET /api/v1/traces
 */
export async function fetchTraces(baseUrl?: string): Promise<TraceSummary[]> {
  return request<TraceSummary[]>('/api/v1/traces', baseUrl);
}

/**
 * Get all normalized spans for a specific trace: GET /api/v1/traces/{trace_id}
 */
export async function fetchTraceSpans(traceId: string, baseUrl?: string): Promise<SpanRecord[]> {
  if (!traceId) {
    throw new Error('trace_id is required');
  }
  return request<SpanRecord[]>(`/api/v1/traces/${encodeURIComponent(traceId)}`, baseUrl);
}

/**
 * Get recent spans across all traces: GET /api/v1/spans?limit={limit}
 */
export async function fetchRecentSpans(limit: number = 100, baseUrl?: string): Promise<SpanRecord[]> {
  return request<SpanRecord[]>(`/api/v1/spans?limit=${encodeURIComponent(limit)}`, baseUrl);
}
