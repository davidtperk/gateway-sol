import * as chai from "chai";
import * as crypto from "crypto";

import BigNumber from "bignumber.js";
import BN from "bn.js";
import chaiAsPromised from "chai-as-promised";
import chaiBigNumber from "chai-bignumber";
import { ECDSASignature } from "ethereumjs-util";
import { keccak256, toChecksumAddress } from "web3-utils";

// Import chai log helper
import "./logs";

chai.use(chaiAsPromised);
chai.use((chaiBigNumber as any)(BigNumber) as any);
chai.should();

export const { encodeCallData } = require("../../migrations/encode.js");

const networkAddresses = require("../../migrations/networks.js");

export const ETHEREUM_TOKEN_ADDRESS =
    "0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE";

// Generate a 20-byte identifier
export function ID(i: string | number) {
    return toChecksumAddress(keccak256(i.toString()).slice(0, 42));
}

// Generate a 32-byte public key
export function PUBK(i: string | number) {
    return keccak256(i.toString());
}

export const NULL = "0x0000000000000000000000000000000000000000";
export const NULL32 =
    "0x0000000000000000000000000000000000000000000000000000000000000000";

// Add a 0x prefix to a hex value, converting to a string first
export const Ox = (hex: string | BN | Buffer) => {
    const hexString = typeof hex === "string" ? hex : hex.toString("hex");
    return hexString.substring(0, 2) === "0x" ? hexString : `0x${hexString}`;
};

export const strip0x = (hex: string) =>
    hex.substring(0, 2) === "0x" ? hex.slice(2) : hex;

export const hexToBuffer = (hex: string | BN | Buffer) =>
    BN.isBN(hex)
        ? hex.toBuffer()
        : Buffer.isBuffer(hex)
        ? hex
        : Buffer.from(strip0x(hex), "hex");

export const randomBytes = (bytes: number): string => {
    return Ox(crypto.randomBytes(bytes));
};

export const randomAddress = (): string => {
    return toChecksumAddress(randomBytes(20));
};

const increaseTimeHelper = async (seconds: number) => {
    await new Promise((resolve, reject) => {
        // tslint:disable-next-line: no-floating-promises
        return web3.currentProvider.send(
            {
                jsonrpc: "2.0",
                method: "evm_increaseTime",
                params: [seconds],
                id: 0,
            } as any,
            ((err: Error) => {
                if (err) {
                    reject(err);
                }
                // tslint:disable-next-line: no-floating-promises
                return web3.currentProvider.send(
                    {
                        jsonrpc: "2.0",
                        method: "evm_mine",
                        params: [],
                        id: new Date().getSeconds(),
                    } as any,
                    ((innerErr: Error) => {
                        if (innerErr) {
                            reject();
                        }
                        resolve();
                    }) as any
                );
            }) as any
        );
    });
};

export const getCurrentTimestamp = async (): Promise<number> =>
    parseInt(
        (
            await web3.eth.getBlock(await web3.eth.getBlockNumber())
        ).timestamp.toString(),
        10
    );

export const increaseTime = async (seconds: number) => {
    let currentTimestamp = await getCurrentTimestamp();
    const target = currentTimestamp + seconds;
    do {
        const increase = Math.ceil(target - currentTimestamp + 1);
        await increaseTimeHelper(increase);
        currentTimestamp = await getCurrentTimestamp();
    } while (currentTimestamp < target);
};

export const randomID = () => {
    return keccak256(Math.random().toString());
};

export const deployProxy = async <T>(
    web3: Web3,
    ProxyContract: Truffle.Contract<any>,
    LogicContract: Truffle.Contract<any>,
    proxyGovernanceAddress: string,
    params: { type: string; value: any; name?: string }[],
    options?: { from: string }
): Promise<T> => {
    const logicContract = await LogicContract.new();
    const proxy = await ProxyContract.new();

    await proxy.initialize(
        logicContract.address,
        proxyGovernanceAddress,
        encodeCallData(
            "initialize",
            params.map((p) => p.type),
            params.map((p) => p.value)
        ),
        options
    );
    return await LogicContract.at(proxy.address);
};

export const sigToString = (sig: ECDSASignature) => {
    return Ox(
        `${sig.r.toString("hex")}${sig.s.toString("hex")}${sig.v.toString(16)}`
    );
};

export const sleep = (ms: number) =>
    new Promise((resolve) => setTimeout(resolve, ms));
