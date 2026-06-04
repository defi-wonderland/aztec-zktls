/**
 * Multi-contract setup helpers for OptionEscrowLogic tests.
 *
 * Mirrors patterns from aztec-escrow-extensions/src/ts/utils.ts but trimmed
 * to what the option_escrow tests actually need: Token deployment with a
 * minter, Escrow class id lookup, and authwit creation.
 */
import { Contract } from "@aztec/aztec.js/contracts";
import { Fr } from "@aztec/aztec.js/fields";
import type { AuthWitness } from "@aztec/stdlib/auth-witness";
import { AztecAddress } from "@aztec/aztec.js/addresses";
import type { Wallet } from "@aztec/aztec.js/wallet";
import type { ContractFunctionInteraction } from "@aztec/aztec.js/contracts";
import { getContractClassFromArtifact } from "@aztec/stdlib/contract";
import type { EmbeddedWallet } from "@aztec/wallets/embedded";

import {
  TokenContract,
  TokenContractArtifact,
} from "@defi-wonderland/aztec-standards/dist/src/artifacts/Token.js";
import { EscrowContractArtifact } from "@defi-wonderland/aztec-standards/dist/src/artifacts/Escrow.js";

/**
 * Deploy a Token contract with the specified minter (typically the deployer).
 * The deployer can then mint balances to test accounts.
 */
export async function deployTokenWithMinter(
  wallet: Wallet,
  deployer: AztecAddress,
  name = "TestToken",
  symbol = "TT",
): Promise<TokenContract> {
  const result = await Contract.deploy(
    wallet,
    TokenContractArtifact,
    [name, symbol, 18, deployer],
    "constructor_with_minter",
  ).send({ from: deployer });
  return result.contract as TokenContract;
}

/** Class id of the aztec-standards Escrow contract — needed by the
 *  OptionEscrowLogic constructor as `escrow_class_id`. */
export async function getEscrowClassId(): Promise<Fr> {
  const cls = await getContractClassFromArtifact(EscrowContractArtifact);
  return cls.id;
}

/**
 * Create a private authwit so a calling contract can move `authorizer`'s
 * tokens via Token::transfer_private_to_private inside a private call.
 * The wallet adds the witness to its in-memory pool — it isn't published.
 */
export async function setPrivateAuthWit(
  caller: AztecAddress,
  action: ContractFunctionInteraction,
  authorizer: AztecAddress,
  wallet: EmbeddedWallet,
): Promise<AuthWitness> {
  return wallet.createAuthWit(authorizer, {
    caller,
    call: await action.getFunctionCall(),
  });
}

/** Random Fr nonce — used to disambiguate concurrent transfers in authwits. */
export function randomNonce(): Fr {
  return Fr.random();
}

/** Random Fr secret — used to derive a per-option Escrow address. */
export function randomSecretKey(): Fr {
  return Fr.random();
}
