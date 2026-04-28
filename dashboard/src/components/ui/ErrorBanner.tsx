import { useEffect } from "react";

interface ErrorBannerProps {
  message: string | null;
  onDismiss: () => void;
  timeout?: number;
}

export function ErrorBanner({
  message,
  onDismiss,
  timeout = 5000,
}: ErrorBannerProps) {
  useEffect(() => {
    if (!message) return;
    const timer = setTimeout(onDismiss, timeout);
    return () => clearTimeout(timer);
  }, [message, onDismiss, timeout]);

  if (!message) return null;

  return (
    <div
      role="alert"
      className="flex items-start gap-2 bg-red/10 border border-red/30 text-red rounded-md px-4 py-3 text-sm mb-4"
    >
      <svg
        aria-hidden
        viewBox="0 0 20 20"
        fill="currentColor"
        className="h-4 w-4 shrink-0 mt-0.5"
      >
        <path
          fillRule="evenodd"
          d="M10 18a8 8 0 100-16 8 8 0 000 16zM9 9a1 1 0 112 0v4a1 1 0 11-2 0V9zm1-5a1 1 0 100 2 1 1 0 000-2z"
          clipRule="evenodd"
        />
      </svg>
      <span>{message}</span>
    </div>
  );
}
