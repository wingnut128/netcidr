import { Panel } from "../ui/Panel";
import { fmtNum } from "../../lib/format";
import type { FreeBlock } from "../../types";

export function FreeBlocksList({ blocks }: { blocks: FreeBlock[] }) {
  return (
    <Panel title="Free Blocks">
      {blocks.length === 0 ? (
        <p className="text-text-muted text-center py-4">No free blocks.</p>
      ) : (
        <div className="space-y-1">
          {blocks.map((b) => (
            <div
              key={b.cidr}
              className="flex justify-between py-1 border-b border-border"
            >
              <span className="text-cyan">{b.cidr}</span>
              <span className="text-text-muted text-[11px]">
                {fmtNum(b.size)} addresses
              </span>
            </div>
          ))}
        </div>
      )}
    </Panel>
  );
}
