interface PageHeaderProps {
  title: string;
  subtitle?: string;
}

export function PageHeader({ title, subtitle }: PageHeaderProps) {
  return (
    <div className="mb-6 pb-4 border-b border-border">
      <h1 className="text-2xl font-semibold tracking-tight text-text">
        {title}
      </h1>
      {subtitle && (
        <p className="text-sm text-text-muted mt-1">{subtitle}</p>
      )}
    </div>
  );
}
