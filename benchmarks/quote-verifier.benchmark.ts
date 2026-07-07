import path from "node:path";
import { AztecAddress } from "@aztec/aztec.js/addresses";
import { type ContractFunctionInteractionCallIntent } from "@aztec/aztec.js/authorization";
import { createAztecNodeClient, waitForNode } from "@aztec/aztec.js/node";
import { Barretenberg } from "@aztec/bb.js";
import { EmbeddedWallet } from "@aztec/wallets/embedded";
import { registerInitialLocalNetworkAccountsInWallet } from "@aztec/wallets/testing";
import {
  Benchmark,
  type BenchmarkContext,
} from "@defi-wonderland/aztec-benchmark";

import { QuoteVerifierContract } from "../src/artifacts/QuoteVerifier.js";
import {
  MAX_RR_LEN,
  MAX_URL_LEN,
  hashAllowedAttestationsFromWitness,
  loadWitness,
  type Witness,
} from "../src/ts/utils.js";

const FIXTURE_PATH = path.resolve(
  import.meta.dirname,
  "../src/ts/fixtures/binance-ETHUSDT.witness.json",
);

interface QuoteVerifierBenchmarkContext extends BenchmarkContext {
  wallet: EmbeddedWallet;
  deployer: AztecAddress;
  accounts: AztecAddress[];
  contract: QuoteVerifierContract;
  witness: Witness;
}

export default class QuoteVerifierBenchmark extends Benchmark {
  /**
   * Deploys a fresh QuoteVerifier seeded with the fixture's URL allow-list and
   * attestor pubkey, ready for a verify(...) call.
   */
  async setup(): Promise<QuoteVerifierBenchmarkContext> {
    const aztecNode = createAztecNodeClient("http://localhost:8080");
    await waitForNode(aztecNode);

    const wallet = await EmbeddedWallet.create(aztecNode);
    const accounts = await registerInitialLocalNetworkAccountsInWallet(wallet);
    const [deployer] = accounts;

    const witness = loadWitness(FIXTURE_PATH);

    const bb = await Barretenberg.new();
    const allowedAttestationHashes = await hashAllowedAttestationsFromWitness(
      bb,
      witness.allowedUrls,
      witness.allowedResponseResolves,
      MAX_URL_LEN,
      MAX_RR_LEN,
    );
    await bb.destroy();

    const initialAttestor = { x: witness.publicKeyX, y: witness.publicKeyY };
    const { contract } = await QuoteVerifierContract.deploy(
      wallet,
      allowedAttestationHashes,
      initialAttestor,
    ).send({ from: deployer });

    return { wallet, deployer, accounts, contract, witness };
  }

  /**
   * Benchmarks a single verify(...) call against the committed witness fixture.
   */
  getMethods(
    context: QuoteVerifierBenchmarkContext,
  ): ContractFunctionInteractionCallIntent[] {
    const { contract, wallet, deployer, witness } = context;

    const envelope = {
      recipient: witness.recipient,
      request_url: witness.requestUrls[0]!,
      request_hmb: witness.requestHmb,
      response_resolves: witness.responseResolves,
      data: witness.data,
      att_conditions: witness.attConditions,
      timestamp: BigInt(witness.timestamp),
      addition_params: witness.additionParams,
    };

    return [
      {
        caller: deployer,
        action: contract
          .withWallet(wallet)
          .methods.verify(
            witness.signature,
            envelope,
            witness.plainJsonResponses,
            witness.dataHashOffsets,
          ),
      },
    ];
  }
}
