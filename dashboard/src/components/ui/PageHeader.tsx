interface PageHeaderProps {
  title: string;
  subtitle?: string;
}

export function PageHeader({ title, subtitle }: PageHeaderProps) {
  return (
    <div className="mb-6 pb-4 border-b-[3px] border-border">
      <h1 className="text-lg font-bold uppercase tracking-[0.15em] text-text">
        {title}
      </h1>
      {subtitle && (
        <p className="text-[11px] text-text-muted uppercase tracking-[0.1em] mt-1">
          {subtitle}
        </p>
      )}
    </div>
  );
}
