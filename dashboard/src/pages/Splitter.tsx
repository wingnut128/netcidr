import { useState, useCallback, useMemo } from "react";
import { get } from "../api";
import type {
  Ipv4Subnet,
  Ipv6Subnet,
  SplitResult,
  SplitTreeNode,
  SplitTreeResult,
  VlsmResult,
} from "../types";
import { fmtSize } from "../lib/format";
import {
  fmtAddressCount,
  MAX_TREE_SUBNETS,
  parsePrefixList,
  treeSubnetCount,
} from "../lib/split";
import { PageHeader } from "../components/ui/PageHeader";
import { Panel } from "../components/ui/Panel";
import { StatCard } from "../components/ui/StatCard";
import { ErrorBanner } from "../components/ui/ErrorBanner";

type Mode = "fixed" | "vlsm" | "steps";

type Result =
  | { mode: "fixed"; data: SplitResult }
  | { mode: "vlsm"; data: VlsmResult }
  | { mode: "steps"; data: SplitTreeResult };

const MODES: { id: Mode; label: string }[] = [
  { id: "fixed", label: "Fixed" },
  { id: "vlsm", label: "VLSM" },
  { id: "steps", label: "Steps" },
];

const INPUT_CLASS =
  "w-full font-mono text-base md:text-sm px-3 py-2 bg-bg border border-border text-text outline-none focus:border-cyan";
const LABEL_CLASS = "block text-xs font-medium text-text-muted mb-1";
const TH_CLASS =
  "text-left px-3 py-2 text-xs font-semibold text-text-muted bg-surface2 border-b-2 border-border";
const TD_CLASS = "px-3 py-2 border-b border-border";
const SMALL_BTN =
  "text-xs font-medium rounded-md px-2.5 py-1 border border-border text-text-muted bg-surface hover:bg-surface2 cursor-pointer transition-colors";

function isV4Subnet(s: unknown): s is Ipv4Subnet {
  return typeof s === "object" && s !== null && "broadcast_address" in s;
}

function totalOf(s: Ipv4Subnet | Ipv6Subnet): string {
  return fmtSize(
    isV4Subnet(s)
      ? s.total_hosts
      : ((s as { total_addresses?: string }).total_addresses ?? 0),
  );
}

/** Prefix length of the input CIDR; a bare address is a host route. */
function parentPrefixOf(cidr: string, v6: boolean): number {
  const [, len] = cidr.split("/");
  return len === undefined ? (v6 ? 128 : 32) : Number(len);
}

function ModeTabs({
  mode,
  onChange,
}: {
  mode: Mode;
  onChange: (m: Mode) => void;
}) {
  const baseBtn =
    "px-3 py-1.5 text-xs font-medium border border-border first:rounded-l-md last:rounded-r-md -ml-px first:ml-0 transition-colors";
  const activeBtn = "bg-cyan/10 text-cyan border-cyan/40 z-10 relative";
  const idleBtn = "bg-surface text-text-muted hover:bg-surface2";
  return (
    <div role="tablist" aria-label="Split mode" className="inline-flex mb-4">
      {MODES.map((m) => (
        <button
          key={m.id}
          type="button"
          role="tab"
          aria-selected={mode === m.id}
          className={`${baseBtn} ${mode === m.id ? activeBtn : idleBtn}`}
          onClick={() => onChange(m.id)}
        >
          {m.label}
        </button>
      ))}
    </div>
  );
}

function SubnetTable({
  subnets,
  isV4,
}: {
  subnets: (Ipv4Subnet | Ipv6Subnet)[];
  isV4: boolean;
}) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse text-xs">
        <thead>
          <tr>
            <th className={TH_CLASS}>#</th>
            <th className={TH_CLASS}>CIDR</th>
            <th className={TH_CLASS}>Network</th>
            {isV4 && <th className={TH_CLASS}>Broadcast</th>}
            <th className={TH_CLASS}>Total</th>
            {isV4 && <th className={TH_CLASS}>Usable</th>}
          </tr>
        </thead>
        <tbody>
          {subnets.map((s, i) => (
            <tr key={i} className="hover:bg-cyan/[0.03]">
              <td className={`${TD_CLASS} text-text-muted`}>{i + 1}</td>
              <td className={`${TD_CLASS} text-cyan`}>{s.input}</td>
              <td className={TD_CLASS}>{s.network_address}</td>
              {isV4 && isV4Subnet(s) && (
                <td className={TD_CLASS}>{s.broadcast_address}</td>
              )}
              <td className={TD_CLASS}>{totalOf(s)}</td>
              {isV4 && isV4Subnet(s) && (
                <td className={TD_CLASS}>{fmtSize(s.usable_hosts)}</td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

interface TreeRow {
  node: SplitTreeNode;
  depth: number;
}

/** Visible rows: the root's children, plus descendants of expanded nodes. */
function visibleRows(root: SplitTreeNode, expanded: Set<string>): TreeRow[] {
  const rows: TreeRow[] = [];
  const walk = (nodes: SplitTreeNode[], depth: number) => {
    for (const node of nodes) {
      rows.push({ node, depth });
      if (node.children.length > 0 && expanded.has(node.subnet.input)) {
        walk(node.children, depth + 1);
      }
    }
  };
  walk(root.children, 0);
  return rows;
}

function allParents(root: SplitTreeNode): Set<string> {
  const keys = new Set<string>();
  const walk = (node: SplitTreeNode) => {
    if (node.children.length === 0) return;
    keys.add(node.subnet.input);
    node.children.forEach(walk);
  };
  root.children.forEach(walk);
  return keys;
}

function SplitTreeTable({
  tree,
  isV4,
}: {
  tree: SplitTreeResult;
  isV4: boolean;
}) {
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const rows = useMemo(
    () => visibleRows(tree.root, expanded),
    [tree.root, expanded],
  );

  const toggle = (key: string) =>
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });

  return (
    <Panel
      title="Subnet tree"
      actions={
        <div className="flex gap-2">
          <button
            type="button"
            className={SMALL_BTN}
            onClick={() => setExpanded(allParents(tree.root))}
          >
            EXPAND ALL
          </button>
          <button
            type="button"
            className={SMALL_BTN}
            onClick={() => setExpanded(new Set())}
          >
            COLLAPSE ALL
          </button>
        </div>
      }
    >
      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-xs">
          <thead>
            <tr>
              <th className={TH_CLASS}>CIDR</th>
              <th className={TH_CLASS}>Network</th>
              {isV4 && <th className={TH_CLASS}>Broadcast</th>}
              <th className={TH_CLASS}>Total</th>
              <th className={TH_CLASS}>Children</th>
            </tr>
          </thead>
          <tbody>
            {rows.map(({ node, depth }) => {
              const s = node.subnet;
              const hasChildren = node.children.length > 0;
              const open = expanded.has(s.input);
              return (
                <tr key={s.input} className="hover:bg-cyan/[0.03]">
                  <td className={TD_CLASS}>
                    <div
                      className="flex items-center gap-1.5"
                      style={{ paddingLeft: `${depth * 20}px` }}
                    >
                      {hasChildren ? (
                        <button
                          type="button"
                          aria-label={`${open ? "Collapse" : "Expand"} ${s.input}`}
                          aria-expanded={open}
                          className="w-5 h-5 inline-flex items-center justify-center font-mono text-text-muted border border-border rounded-sm hover:text-cyan hover:border-cyan/40 cursor-pointer"
                          onClick={() => toggle(s.input)}
                        >
                          {open ? "-" : "+"}
                        </button>
                      ) : (
                        <span className="w-5" aria-hidden />
                      )}
                      <span className="text-cyan">{s.input}</span>
                    </div>
                  </td>
                  <td className={TD_CLASS}>{s.network_address}</td>
                  {isV4 && (
                    <td className={TD_CLASS}>
                      {isV4Subnet(s) ? s.broadcast_address : ""}
                    </td>
                  )}
                  <td className={TD_CLASS}>{totalOf(s)}</td>
                  <td className={`${TD_CLASS} text-text-muted`}>
                    {hasChildren ? node.children.length : ""}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </Panel>
  );
}

export function Splitter() {
  const [mode, setMode] = useState<Mode>("fixed");
  const [cidr, setCidr] = useState("");
  const [prefix, setPrefix] = useState("");
  const [count, setCount] = useState("");
  const [max, setMax] = useState(false);
  const [prefixList, setPrefixList] = useState("");
  const [result, setResult] = useState<Result | null>(null);
  const [isV4, setIsV4] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const changeMode = useCallback((m: Mode) => {
    setMode(m);
    setResult(null);
    setError(null);
  }, []);

  const doSplit = useCallback(async () => {
    const input = cidr.trim();
    if (!input) return;
    const v6 = input.includes(":");
    const family = v6 ? "/v6" : "/v4";
    const cidrQs = `cidr=${encodeURIComponent(input)}`;
    try {
      if (mode === "fixed") {
        if (!prefix) return;
        let qs = `${cidrQs}&prefix=${prefix}`;
        qs += max || !count ? "&max=true" : `&count=${count}`;
        const data = await get<SplitResult>(`${family}/split?${qs}`);
        setResult({ mode, data });
      } else {
        const lengths = parsePrefixList(prefixList);
        const list = encodeURIComponent(lengths.join(","));
        if (mode === "vlsm") {
          const data = await get<VlsmResult>(
            `${family}/vlsm?${cidrQs}&prefixes=${list}`,
          );
          setResult({ mode, data });
        } else {
          const n = treeSubnetCount(parentPrefixOf(input, v6), lengths);
          if (n > MAX_TREE_SUBNETS) {
            throw new Error(
              `This split would generate ${n.toLocaleString("en-US")} subnets; ` +
                `the dashboard limit is ${MAX_TREE_SUBNETS.toLocaleString("en-US")}. ` +
                "Use the CLI or API for larger trees.",
            );
          }
          const data = await get<SplitTreeResult>(
            `${family}/split-tree?${cidrQs}&steps=${list}`,
          );
          setResult({ mode, data });
        }
      }
      setIsV4(!v6);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unknown error");
      setResult(null);
    }
  }, [mode, cidr, prefix, count, max, prefixList]);

  const listPlaceholder = mode === "vlsm" ? "e.g. 26,28,28" : "e.g. 22,24";

  return (
    <div>
      <PageHeader
        title="Subnet Splitter"
        subtitle="Split a network into fixed-size, variable-length (VLSM), or hierarchical subnets"
      />
      <ErrorBanner message={error} onDismiss={() => setError(null)} />

      <ModeTabs mode={mode} onChange={changeMode} />

      <Panel title="Input">
        <div className="flex gap-3 items-end flex-wrap">
          <div className="flex-[3] min-w-[200px]">
            <label htmlFor="split-cidr" className={LABEL_CLASS}>
              CIDR
            </label>
            <input
              id="split-cidr"
              type="text"
              className={INPUT_CLASS}
              placeholder="e.g. 10.0.0.0/8"
              value={cidr}
              onChange={(e) => setCidr(e.target.value)}
            />
          </div>

          {mode === "fixed" ? (
            <>
              <div className="flex-1 min-w-[100px]">
                <label htmlFor="split-prefix" className={LABEL_CLASS}>
                  Target Prefix
                </label>
                <input
                  id="split-prefix"
                  type="number"
                  className={INPUT_CLASS}
                  placeholder="e.g. 24"
                  min={0}
                  max={128}
                  value={prefix}
                  onChange={(e) => setPrefix(e.target.value)}
                />
              </div>
              <div className="flex-1 min-w-[100px]">
                <label htmlFor="split-count" className={LABEL_CLASS}>
                  Count
                </label>
                <input
                  id="split-count"
                  type="number"
                  className={`${INPUT_CLASS} disabled:opacity-40`}
                  placeholder="max"
                  min={1}
                  value={count}
                  onChange={(e) => setCount(e.target.value)}
                  disabled={max}
                />
              </div>
            </>
          ) : (
            <div className="flex-[2] min-w-[160px]">
              <label htmlFor="split-prefix-list" className={LABEL_CLASS}>
                Prefix lengths
              </label>
              <input
                id="split-prefix-list"
                type="text"
                className={INPUT_CLASS}
                placeholder={listPlaceholder}
                value={prefixList}
                onChange={(e) => setPrefixList(e.target.value)}
              />
            </div>
          )}

          <div className="flex items-center gap-3">
            {mode === "fixed" && (
              <label className="text-xs text-text-muted whitespace-nowrap flex items-center gap-1 cursor-pointer">
                <input
                  type="checkbox"
                  checked={max}
                  onChange={(e) => setMax(e.target.checked)}
                />
                MAX
              </label>
            )}
            <button
              className="text-xs font-medium rounded-md px-4 py-2 min-h-[44px] md:min-h-0 border border-cyan text-cyan bg-surface2 cursor-pointer hover:bg-cyan hover:text-bg transition-colors"
              onClick={doSplit}
            >
              SPLIT
            </button>
          </div>
        </div>
        {mode !== "fixed" && (
          <p className="text-xs text-text-muted mt-2">
            {mode === "vlsm"
              ? "Descending prefix lengths, carved largest block first."
              : "Strictly increasing prefix lengths, applied recursively at each level."}
          </p>
        )}
      </Panel>

      {result?.mode === "fixed" && (
        <>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-5">
            <StatCard
              label="Parent CIDR"
              value={result.data.cidr_block?.input ?? cidr}
              color="cyan"
              valueSize="18px"
            />
            <StatCard
              label="Child Subnets"
              value={result.data.subnets?.length ?? 0}
              color="green"
            />
            <StatCard
              label="New Prefix"
              value={`/${result.data.new_prefix}`}
              color="yellow"
            />
          </div>
          <Panel
            title="Subnets"
            actions={
              <span className="text-xs text-text-muted">
                {result.data.subnets?.length ?? 0} results
              </span>
            }
          >
            <SubnetTable subnets={result.data.subnets ?? []} isV4={isV4} />
          </Panel>
        </>
      )}

      {result?.mode === "vlsm" && (
        <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-5">
            <StatCard
              label="Parent CIDR"
              value={result.data.cidr_block.input}
              color="cyan"
              valueSize="18px"
            />
            <StatCard
              label="Allocations"
              value={result.data.subnets.length}
              color="green"
            />
            <StatCard
              label="Allocated"
              value={fmtAddressCount(result.data.allocated_addresses)}
              color="yellow"
            />
            <StatCard
              label="Remaining"
              value={fmtAddressCount(result.data.remaining_addresses)}
              color="purple"
            />
          </div>
          <Panel
            title="Allocations"
            actions={
              <span className="text-xs text-text-muted">
                {result.data.subnets.length} results
              </span>
            }
          >
            <SubnetTable subnets={result.data.subnets} isV4={isV4} />
          </Panel>
        </>
      )}

      {result?.mode === "steps" && (
        <>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-5">
            <StatCard
              label="Parent CIDR"
              value={result.data.root.subnet.input}
              color="cyan"
              valueSize="18px"
            />
            <StatCard
              label="Total Subnets"
              value={result.data.total_subnets}
              color="green"
            />
            <StatCard
              label="Steps"
              value={result.data.steps.map((s) => `/${s}`).join(" > ")}
              color="yellow"
              valueSize="18px"
            />
          </div>
          <SplitTreeTable
            key={result.data.root.subnet.input + result.data.steps.join(",")}
            tree={result.data}
            isV4={isV4}
          />
        </>
      )}
    </div>
  );
}
