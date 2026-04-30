interface BitGridProps {
  prefixLength: number;
  totalBits: number;
}

export function BitGrid({ prefixLength, totalBits }: BitGridProps) {
  return (
    <div>
      {/* Horizontal scroll on mobile so wide /128 visualizations don't push
          the page wider than the viewport; wrap on md:+ for readability. */}
      <div className="overflow-x-auto -mx-3 px-3 md:mx-0 md:px-0 md:overflow-visible">
        <div className="flex md:flex-wrap gap-px my-3 w-max md:w-auto">
          {Array.from({ length: totalBits }, (_, i) => {
            const isNetwork = i < prefixLength;
            return (
              <div
                key={i}
                className={`w-[18px] h-[18px] border flex items-center justify-center text-[8px] font-bold ${
                  isNetwork
                    ? "bg-cyan text-bg border-cyan"
                    : "bg-surface2 text-text-muted border-border"
                }`}
              >
                {isNetwork ? "1" : "0"}
              </div>
            );
          })}
        </div>
      </div>
      <p className="text-xs text-text-muted mt-2">
        {prefixLength} network bits / {totalBits - prefixLength} host bits
      </p>
    </div>
  );
}
