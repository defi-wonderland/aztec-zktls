/**
 * Chain-time control for tests running against `aztec start --local-network`.
 *
 * Mirrors `@aztec/aztec/testing/cheat_codes.ts::CheatCodes.warpL2TimeAtLeastTo`
 * inline to avoid pulling in the `@aztec/aztec` package just for one method.
 *
 * Mechanism:
 *   1. anvil L1 cheat (`evm_setNextBlockTimestamp` via EthCheatCodes.warp)
 *   2. force the Aztec sequencer to mine an L2 block at that new timestamp
 *      (`nodeDebug.mineBlock()`)
 *
 * Gotchas:
 *   - Target timestamp MUST be strictly in the future of current L1 head.
 *   - Two L2 blocks can't share a slot. If the target lands in the current
 *     slot, `mineBlock` hangs. The wrapper detects this via the Rollup
 *     contract and bumps the target to the next slot's start automatically.
 *   - L2 timestamp ends up ≥ target (snaps to the next slot boundary).
 */
import { EthCheatCodes, RollupCheatCodes } from "@aztec/ethereum/test";
import { DateProvider } from "@aztec/foundation/timer";
import {
  createAztecNodeDebugClient,
  type AztecNodeDebug,
} from "@aztec/stdlib/interfaces/client";
import type { AztecNode } from "@aztec/aztec.js/node";
import { SlotNumber } from "@aztec/foundation/branded-types";

export type ChainTime = {
  /** Warp L1 + mine an L2 block so block.timestamp >= `targetSec`. */
  warpL2TimeAtLeastTo(targetSec: bigint | number): Promise<void>;
  /** Warp by `durationSec` from current L1 head. */
  warpL2TimeAtLeastBy(durationSec: bigint | number): Promise<void>;
  /** Current L2 head's block.timestamp (seconds). */
  currentL2TimestampSec(): Promise<bigint>;
  /** Current L1 (anvil) head's block.timestamp (seconds). L1 advances
   *  autonomously via interval mining, so this is usually ahead of L2. */
  currentL1TimestampSec(): Promise<bigint>;
  /**
   * Wrap a `.send()` promise so the L2 sequencer is force-mined while the tx
   * is pending. Without this each tx waits up to a full L2 slot (~72s); with
   * it the tx lands in the next forced block (~1s). One warp+mine per call to
   * keep chain-time advancement bounded — each tx still moves L2 chain time
   * forward by ≤ 1 slot. */
  withMine<T>(sendPromise: Promise<T>): Promise<T>;
};

const DEFAULT_L1_RPC = "http://localhost:8545";
const DEFAULT_NODE_URL = "http://localhost:8080";

export async function createChainTime(
  node: AztecNode,
  opts: { l1RpcUrl?: string; nodeUrl?: string } = {},
): Promise<ChainTime> {
  const l1RpcUrl = opts.l1RpcUrl ?? DEFAULT_L1_RPC;
  const nodeUrl = opts.nodeUrl ?? DEFAULT_NODE_URL;
  const dateProvider = new DateProvider();
  const eth = new EthCheatCodes([l1RpcUrl], dateProvider);
  const nodeInfo = await node.getNodeInfo();
  const rollup = new RollupCheatCodes(eth, nodeInfo.l1ContractAddresses);
  const nodeDebug: AztecNodeDebug = createAztecNodeDebugClient(nodeUrl);

  async function warpL2TimeAtLeastTo(targetSec: bigint | number) {
    const target = BigInt(targetSec);
    const currentL1 = BigInt(await eth.lastBlockTimestamp());
    if (target <= currentL1) {
      throw new Error(
        `warpL2TimeAtLeastTo: target ${target} is not in the future (L1 head ${currentL1})`,
      );
    }
    const currentSlot = await rollup.getSlot();
    const targetSlot = await rollup.getSlotAt(target);
    let effective = target;
    if (targetSlot <= currentSlot) {
      const nextSlot = SlotNumber.add(currentSlot, 1);
      effective = await rollup.getTimestampForSlot(nextSlot);
    }
    await eth.warp(effective, { resetBlockInterval: true });
    await nodeDebug.mineBlock();
  }

  async function warpL2TimeAtLeastBy(durationSec: bigint | number) {
    const duration = BigInt(durationSec);
    if (duration <= 0n) {
      throw new Error(`warpL2TimeAtLeastBy: duration must be positive`);
    }
    const currentL1 = BigInt(await eth.lastBlockTimestamp());
    await warpL2TimeAtLeastTo(currentL1 + duration);
  }

  async function currentL2TimestampSec(): Promise<bigint> {
    const blockNumber = await node.getBlockNumber();
    const header = await node.getBlockHeader(blockNumber);
    if (!header) {
      throw new Error(`no header for block ${blockNumber}`);
    }
    return BigInt(header.globalVariables.timestamp);
  }

  async function currentL1TimestampSec(): Promise<bigint> {
    return BigInt(await eth.lastBlockTimestamp());
  }

  async function withMine<T>(sendPromise: Promise<T>): Promise<T> {
    // Loop mining the L2 sequencer while the tx is in flight: each iteration
    // bumps L1 by ~1 slot's worth and produces a block. The loop exits as
    // soon as `sendPromise` resolves (receipt arrived). Without this each
    // tx waits a full slot (~72s); with it the tx lands in the next forced
    // block (~1s). Chain time advancement is bounded by the number of slots
    // the tx actually takes to mine.
    let done = false;
    const tracked = sendPromise.finally(() => {
      done = true;
    });
    const minePromise = (async () => {
      // Initial delay so the tx has a chance to hit the mempool. We then
      // re-mine every ~2s while the tx is still in flight. The delay gives
      // the sequencer time to fully commit each forced block before we ask
      // for the next one — too tight a loop causes "block not found / reorg"
      // errors as we race the sequencer.
      await new Promise((r) => setTimeout(r, 1500));
      while (!done) {
        try {
          await warpL2TimeAtLeastBy(1n);
        } catch {
          // ignore — best effort.
        }
        if (done) break;
        await new Promise((r) => setTimeout(r, 2000));
      }
    })().catch(() => {});
    try {
      return await tracked;
    } finally {
      await minePromise;
    }
  }

  return {
    warpL2TimeAtLeastTo,
    warpL2TimeAtLeastBy,
    currentL2TimestampSec,
    currentL1TimestampSec,
    withMine,
  };
}
