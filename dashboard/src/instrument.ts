import { useEffect } from "react";
import {
  createRoutesFromChildren,
  matchRoutes,
  useLocation,
  useNavigationType,
} from "react-router-dom";
import * as Sentry from "@sentry/react";

// Must be the first import in main.tsx so the SDK is live before any app code
// runs. The DSN is baked in at build time; when VITE_SENTRY_DSN is unset the
// SDK stays disabled, so self-built binaries report nothing.
const dsn = import.meta.env.VITE_SENTRY_DSN as string | undefined;

Sentry.init({
  dsn,
  environment: import.meta.env.MODE,
  release: import.meta.env.VITE_APP_VERSION as string | undefined,

  // The dashboard sends bearer credentials (OIDC ID tokens, PATs) on every
  // /ipam request and renders freshly minted PAT secrets. Keep all of that
  // out of events: no user IP/headers, no cookies, no HTTP headers or bodies.
  dataCollection: {
    userInfo: false,
    cookies: false,
    httpHeaders: false,
    httpBodies: [],
  },

  integrations: [
    Sentry.reactRouterV7BrowserTracingIntegration({
      useEffect,
      useLocation,
      useNavigationType,
      createRoutesFromChildren,
      matchRoutes,
    }),
    Sentry.replayIntegration({
      maskAllText: true,
      maskAllInputs: true,
      blockAllMedia: true,
    }),
  ],

  tracesSampleRate: import.meta.env.DEV ? 1.0 : 0.1,
  // The API is same-origin (relative URLs), so only propagate trace headers there.
  tracePropagationTargets: [/^\//],

  replaysSessionSampleRate: 0.1,
  replaysOnErrorSampleRate: 1.0,
});
