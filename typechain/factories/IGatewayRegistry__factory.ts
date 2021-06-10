/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */

import { Contract, Signer, utils } from "ethers";
import { Provider } from "@ethersproject/providers";
import type {
  IGatewayRegistry,
  IGatewayRegistryInterface,
} from "../IGatewayRegistry";

const _abi = [
  {
    anonymous: false,
    inputs: [
      {
        indexed: false,
        internalType: "string",
        name: "_symbol",
        type: "string",
      },
      {
        indexed: true,
        internalType: "string",
        name: "_indexedSymbol",
        type: "string",
      },
      {
        indexed: true,
        internalType: "address",
        name: "_tokenAddress",
        type: "address",
      },
      {
        indexed: true,
        internalType: "address",
        name: "_gatewayAddress",
        type: "address",
      },
    ],
    name: "LogGatewayDeregistered",
    type: "event",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: false,
        internalType: "string",
        name: "_symbol",
        type: "string",
      },
      {
        indexed: true,
        internalType: "string",
        name: "_indexedSymbol",
        type: "string",
      },
      {
        indexed: true,
        internalType: "address",
        name: "_tokenAddress",
        type: "address",
      },
      {
        indexed: true,
        internalType: "address",
        name: "_gatewayAddress",
        type: "address",
      },
    ],
    name: "LogGatewayRegistered",
    type: "event",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: "address",
        name: "_tokenAddress",
        type: "address",
      },
      {
        indexed: true,
        internalType: "address",
        name: "_currentGatewayAddress",
        type: "address",
      },
      {
        indexed: true,
        internalType: "address",
        name: "_newGatewayAddress",
        type: "address",
      },
    ],
    name: "LogGatewayUpdated",
    type: "event",
  },
  {
    constant: true,
    inputs: [
      {
        internalType: "string",
        name: "_tokenSymbol",
        type: "string",
      },
    ],
    name: "getGatewayBySymbol",
    outputs: [
      {
        internalType: "contract IGateway",
        name: "",
        type: "address",
      },
    ],
    payable: false,
    stateMutability: "view",
    type: "function",
  },
  {
    constant: true,
    inputs: [
      {
        internalType: "address",
        name: "_tokenAddress",
        type: "address",
      },
    ],
    name: "getGatewayByToken",
    outputs: [
      {
        internalType: "contract IGateway",
        name: "",
        type: "address",
      },
    ],
    payable: false,
    stateMutability: "view",
    type: "function",
  },
  {
    constant: true,
    inputs: [
      {
        internalType: "address",
        name: "_start",
        type: "address",
      },
      {
        internalType: "uint256",
        name: "_count",
        type: "uint256",
      },
    ],
    name: "getGateways",
    outputs: [
      {
        internalType: "address[]",
        name: "",
        type: "address[]",
      },
    ],
    payable: false,
    stateMutability: "view",
    type: "function",
  },
  {
    constant: true,
    inputs: [
      {
        internalType: "address",
        name: "_start",
        type: "address",
      },
      {
        internalType: "uint256",
        name: "_count",
        type: "uint256",
      },
    ],
    name: "getRenTokens",
    outputs: [
      {
        internalType: "address[]",
        name: "",
        type: "address[]",
      },
    ],
    payable: false,
    stateMutability: "view",
    type: "function",
  },
  {
    constant: true,
    inputs: [
      {
        internalType: "string",
        name: "_tokenSymbol",
        type: "string",
      },
    ],
    name: "getTokenBySymbol",
    outputs: [
      {
        internalType: "contract IERC20",
        name: "",
        type: "address",
      },
    ],
    payable: false,
    stateMutability: "view",
    type: "function",
  },
];

export class IGatewayRegistry__factory {
  static readonly abi = _abi;
  static createInterface(): IGatewayRegistryInterface {
    return new utils.Interface(_abi) as IGatewayRegistryInterface;
  }
  static connect(
    address: string,
    signerOrProvider: Signer | Provider
  ): IGatewayRegistry {
    return new Contract(address, _abi, signerOrProvider) as IGatewayRegistry;
  }
}
