/**
 * Thin API client wrapping fetch.
 * All endpoints are relative to the server root.
 */

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

import { getCurrentIdToken } from "./auth/oidc";

async function request<T>(
  method: string,
  path: string,
  body?: unknown,
  expectNoContent = false,
): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  const idToken = getCurrentIdToken();
  if (idToken) headers["Authorization"] = `Bearer ${idToken}`;

  const opts: RequestInit = { method, headers };
  if (body !== undefined) {
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(path, opts);
  if (!res.ok) {
    const text = await res.text();
    let message = text;
    try {
      const json = JSON.parse(text) as { error?: string };
      if (json.error) message = json.error;
    } catch {
      // use raw text
    }
    throw new ApiError(res.status, message);
  }
  if (expectNoContent) return undefined as T;
  return (await res.json()) as T;
}

export function get<T>(path: string): Promise<T> {
  return request<T>("GET", path);
}

export function post<T>(path: string, body?: unknown): Promise<T> {
  return request<T>("POST", path, body);
}

export function patch<T>(path: string, body?: unknown): Promise<T> {
  return request<T>("PATCH", path, body);
}

export function put<T>(path: string, body?: unknown): Promise<T> {
  return request<T>("PUT", path, body);
}

export function del<T>(path: string): Promise<T> {
  return request<T>("DELETE", path);
}

export function delVoid(path: string): Promise<void> {
  return request<void>("DELETE", path, undefined, true);
}
