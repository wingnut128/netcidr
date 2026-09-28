import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { Splitter } from "./Splitter";

const mocks = vi.hoisted(() => ({ get: vi.fn() }));

vi.mock("../api", () => ({ get: mocks.get }));

function v4(input: string, network: string, broadcast: string, total: number) {
  return {
    input,
    network_address: network,
    broadcast_address: broadcast,
    total_hosts: total,
    usable_hosts: Math.max(total - 2, 0),
  };
}

async function selectMode(name: RegExp) {
  await userEvent.click(screen.getByRole("tab", { name }));
}

describe("Splitter", () => {
  beforeEach(() => {
    mocks.get.mockReset();
  });

  it("defaults to fixed mode and calls /v4/split", async () => {
    mocks.get.mockResolvedValue({
      cidr_block: v4("10.0.0.0/24", "10.0.0.0", "10.0.0.255", 256),
      subnets: [v4("10.0.0.0/25", "10.0.0.0", "10.0.0.127", 128)],
      new_prefix: 25,
    });
    render(<Splitter />);

    expect(screen.getByRole("tab", { name: /fixed/i })).toHaveAttribute(
      "aria-selected",
      "true",
    );
    await userEvent.type(screen.getByLabelText(/^cidr$/i), "10.0.0.0/24");
    await userEvent.type(screen.getByLabelText(/target prefix/i), "25");
    await userEvent.click(screen.getByRole("button", { name: "SPLIT" }));

    expect(mocks.get).toHaveBeenCalledWith(
      "/v4/split?cidr=10.0.0.0%2F24&prefix=25&max=true",
    );
    expect(await screen.findByText("10.0.0.0/25")).toBeInTheDocument();
  });

  it("VLSM mode calls /v4/vlsm and shows allocated/remaining", async () => {
    mocks.get.mockResolvedValue({
      cidr_block: v4("10.0.0.0/24", "10.0.0.0", "10.0.0.255", 256),
      requested_count: 3,
      subnets: [
        v4("10.0.0.0/26", "10.0.0.0", "10.0.0.63", 64),
        v4("10.0.0.64/28", "10.0.0.64", "10.0.0.79", 16),
        v4("10.0.0.80/28", "10.0.0.80", "10.0.0.95", 16),
      ],
      allocated_addresses: "96",
      remaining_addresses: "160",
    });
    render(<Splitter />);

    await selectMode(/vlsm/i);
    expect(screen.queryByLabelText(/target prefix/i)).not.toBeInTheDocument();
    await userEvent.type(screen.getByLabelText(/^cidr$/i), "10.0.0.0/24");
    await userEvent.type(screen.getByLabelText(/prefix lengths/i), "26, 28, 28");
    await userEvent.click(screen.getByRole("button", { name: "SPLIT" }));

    expect(mocks.get).toHaveBeenCalledWith(
      "/v4/vlsm?cidr=10.0.0.0%2F24&prefixes=26%2C28%2C28",
    );
    expect(await screen.findByText("10.0.0.80/28")).toBeInTheDocument();
    expect(screen.getByText("96")).toBeInTheDocument();
    expect(screen.getByText("160")).toBeInTheDocument();
  });

  it("uses the IPv6 VLSM endpoint for IPv6 input", async () => {
    mocks.get.mockResolvedValue({
      cidr_block: { input: "2001:db8::/48", network_address: "2001:db8::" },
      requested_count: 1,
      subnets: [{ input: "2001:db8::/52", network_address: "2001:db8::" }],
      allocated_addresses: "1",
      remaining_addresses: "15",
    });
    render(<Splitter />);

    await selectMode(/vlsm/i);
    await userEvent.type(screen.getByLabelText(/^cidr$/i), "2001:db8::/48");
    await userEvent.type(screen.getByLabelText(/prefix lengths/i), "52");
    await userEvent.click(screen.getByRole("button", { name: "SPLIT" }));

    expect(mocks.get).toHaveBeenCalledWith(
      "/v6/vlsm?cidr=2001%3Adb8%3A%3A%2F48&prefixes=52",
    );
  });

  it("Steps mode renders a collapsible tree from /v4/split-tree", async () => {
    const leaf = (c: string, n: string, b: string) => ({
      subnet: v4(c, n, b, 256),
      children: [],
    });
    mocks.get.mockResolvedValue({
      root: {
        subnet: v4("10.0.0.0/22", "10.0.0.0", "10.0.3.255", 1024),
        children: [
          {
            subnet: v4("10.0.0.0/23", "10.0.0.0", "10.0.1.255", 512),
            children: [
              leaf("10.0.0.0/24", "10.0.0.0", "10.0.0.255"),
              leaf("10.0.1.0/24", "10.0.1.0", "10.0.1.255"),
            ],
          },
          {
            subnet: v4("10.0.2.0/23", "10.0.2.0", "10.0.3.255", 512),
            children: [
              leaf("10.0.2.0/24", "10.0.2.0", "10.0.2.255"),
              leaf("10.0.3.0/24", "10.0.3.0", "10.0.3.255"),
            ],
          },
        ],
      },
      steps: [23, 24],
      total_subnets: 6,
    });
    render(<Splitter />);

    await selectMode(/steps/i);
    await userEvent.type(screen.getByLabelText(/^cidr$/i), "10.0.0.0/22");
    await userEvent.type(screen.getByLabelText(/prefix lengths/i), "23,24");
    await userEvent.click(screen.getByRole("button", { name: "SPLIT" }));

    expect(mocks.get).toHaveBeenCalledWith(
      "/v4/split-tree?cidr=10.0.0.0%2F22&steps=23%2C24",
    );

    // First level visible, deeper levels collapsed.
    const first = await screen.findByText("10.0.0.0/23");
    expect(screen.getByText("10.0.2.0/23")).toBeInTheDocument();
    expect(screen.queryByText("10.0.1.0/24")).not.toBeInTheDocument();

    const row = first.closest("tr");
    expect(row).not.toBeNull();
    await userEvent.click(
      within(row as HTMLElement).getByRole("button", { name: /expand/i }),
    );
    expect(screen.getByText("10.0.1.0/24")).toBeInTheDocument();
    expect(screen.queryByText("10.0.3.0/24")).not.toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "EXPAND ALL" }));
    expect(screen.getByText("10.0.3.0/24")).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "COLLAPSE ALL" }));
    expect(screen.queryByText("10.0.1.0/24")).not.toBeInTheDocument();
  });

  it("refuses trees too large to render without calling the API", async () => {
    render(<Splitter />);

    await selectMode(/steps/i);
    await userEvent.type(screen.getByLabelText(/^cidr$/i), "10.0.0.0/8");
    await userEvent.type(screen.getByLabelText(/prefix lengths/i), "16,24");
    await userEvent.click(screen.getByRole("button", { name: "SPLIT" }));

    expect(mocks.get).not.toHaveBeenCalled();
    expect(
      await screen.findByText(/65,792 subnets.*limit is 4,096/i),
    ).toBeInTheDocument();
  });

  it("reports an invalid prefix list without calling the API", async () => {
    render(<Splitter />);

    await selectMode(/vlsm/i);
    await userEvent.type(screen.getByLabelText(/^cidr$/i), "10.0.0.0/24");
    await userEvent.type(screen.getByLabelText(/prefix lengths/i), "26,x");
    await userEvent.click(screen.getByRole("button", { name: "SPLIT" }));

    expect(mocks.get).not.toHaveBeenCalled();
    expect(
      await screen.findByText(/Invalid prefix length: x/),
    ).toBeInTheDocument();
  });
});
