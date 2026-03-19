import { Panel } from "../components/ui/Panel";

export function Placeholder({ name }: { name: string }) {
  return (
    <Panel title={name}>
      <p className="text-text-muted">This page is under construction.</p>
    </Panel>
  );
}
