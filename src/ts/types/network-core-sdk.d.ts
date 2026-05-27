declare module "@primuslabs/network-core-sdk" {
  import type { Wallet } from "ethers";

  export type ResponseResolve = {
    keyName: string;
    parseType: "json" | "html";
    parsePath: string;
    op?: string;
    value?: unknown;
  };

  export type AttestRequest = {
    url: string;
    method: "GET" | "POST" | string;
    header: Record<string, string>;
    body: string;
  };

  export type SubmitTaskParams = { address: string };
  export type SubmitTaskResult = Record<string, unknown>;

  export type AttestParams = SubmitTaskParams &
    SubmitTaskResult & {
      requests: AttestRequest[];
      responseResolves: ResponseResolve[][];
      attMode?: { algorithmType?: "mpctls" | "proxytls" };
      getAllJsonResponse?: "true" | "false";
      mTLS?: { clientKey: string; clientCrt: string };
    };

  export type AttestEntry = {
    taskId: string;
    reportTxHash: string;
    attestation: {
      recipient: string;
      request: AttestRequest | AttestRequest[];
      responseResolves: unknown;
      data: string;
      attConditions: string;
      timestamp: number | string;
      additionParams: string;
    };
    attestor: string;
    signature: string;
    attestationTime?: number;
    attestorUrl?: string;
    [k: string]: unknown;
  };

  export type AllJsonResponseEntry = { id: string; content: string };

  export type VerifyParams = { taskId: string; reportTxHash: string };

  export class PrimusNetwork {
    init(wallet: Wallet, chainId: number, mode?: string): Promise<unknown>;
    submitTask(params: SubmitTaskParams): Promise<SubmitTaskResult>;
    attest(params: AttestParams): Promise<AttestEntry[]>;
    verifyAndPollTaskResult(params: VerifyParams): Promise<unknown>;
    getAllJsonResponse(taskId: string): AllJsonResponseEntry[] | undefined;
    getPlainResponse(taskId: string, index: number, fieldPath: string): string;
  }
}
