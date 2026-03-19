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
    <div className="bg-red/10 border-2 border-red text-red px-4 py-2.5 text-xs mb-4">
      {message}
    </div>
  );
}
