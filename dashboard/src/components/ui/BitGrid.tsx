interface BitGridProps {
  prefixLength: number;
  totalBits: number;
}

export function BitGrid({ prefixLength, totalBits }: BitGridProps) {
  return (
    <div>
      <div className="flex flex-wrap gap-px my-3">
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
      <p className="text-xs text-text-muted mt-2">
        {prefixLength} network bits / {totalBits - prefixLength} host bits
      </p>
    </div>
  );
}
