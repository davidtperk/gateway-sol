/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */

import { Signer, utils, Contract, ContractFactory, Overrides } from "ethers";
import { Provider, TransactionRequest } from "@ethersproject/providers";
import type { Claimable, ClaimableInterface } from "../Claimable";

const _abi = [
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: "address",
        name: "previousOwner",
        type: "address",
      },
      {
        indexed: true,
        internalType: "address",
        name: "newOwner",
        type: "address",
      },
    ],
    name: "OwnershipTransferred",
    type: "event",
  },
  {
    constant: false,
    inputs: [
      {
        internalType: "address",
        name: "newOwner",
        type: "address",
      },
    ],
    name: "_directTransferOwnership",
    outputs: [],
    payable: false,
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    constant: false,
    inputs: [],
    name: "claimOwnership",
    outputs: [],
    payable: false,
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    constant: false,
    inputs: [
      {
        internalType: "address",
        name: "_nextOwner",
        type: "address",
      },
    ],
    name: "initialize",
    outputs: [],
    payable: false,
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    constant: true,
    inputs: [],
    name: "isOwner",
    outputs: [
      {
        internalType: "bool",
        name: "",
        type: "bool",
      },
    ],
    payable: false,
    stateMutability: "view",
    type: "function",
  },
  {
    constant: true,
    inputs: [],
    name: "owner",
    outputs: [
      {
        internalType: "address",
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
    inputs: [],
    name: "pendingOwner",
    outputs: [
      {
        internalType: "address",
        name: "",
        type: "address",
      },
    ],
    payable: false,
    stateMutability: "view",
    type: "function",
  },
  {
    constant: false,
    inputs: [],
    name: "renounceOwnership",
    outputs: [],
    payable: false,
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    constant: false,
    inputs: [
      {
        internalType: "address",
        name: "newOwner",
        type: "address",
      },
    ],
    name: "transferOwnership",
    outputs: [],
    payable: false,
    stateMutability: "nonpayable",
    type: "function",
  },
];

const _bytecode =
  "0x6080604052610c32806100136000396000f3fe608060405234801561001057600080fd5b50600436106100885760003560e01c80638f32d59b1161005b5780638f32d59b1461012f578063c4d66de814610151578063e30c397814610195578063f2fde38b146101df57610088565b8063238e5bc81461008d5780634e71e0c8146100d1578063715018a6146100db5780638da5cb5b146100e5575b600080fd5b6100cf600480360360208110156100a357600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610223565b005b6100d96102a9565b005b6100e36103a8565b005b6100ed6104e3565b604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b61013761050d565b604051808215151515815260200191505060405180910390f35b6101936004803603602081101561016757600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919050505061056c565b005b61019d610675565b604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b610221600480360360208110156101f557600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919050505061069b565b005b61022b61050d565b61029d576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260208152602001807f4f776e61626c653a2063616c6c6572206973206e6f7420746865206f776e657281525060200191505060405180910390fd5b6102a68161085c565b50565b606660009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff166102ea6109a2565b73ffffffffffffffffffffffffffffffffffffffff1614610356576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252602a815260200180610bd4602a913960400191505060405180910390fd5b610381606660009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1661085c565b606660006101000a81549073ffffffffffffffffffffffffffffffffffffffff0219169055565b6103b061050d565b610422576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260208152602001807f4f776e61626c653a2063616c6c6572206973206e6f7420746865206f776e657281525060200191505060405180910390fd5b600073ffffffffffffffffffffffffffffffffffffffff16603360009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff167f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e060405160405180910390a36000603360006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550565b6000603360009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16905090565b6000603360009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff166105506109a2565b73ffffffffffffffffffffffffffffffffffffffff1614905090565b600060019054906101000a900460ff168061058b575061058a6109aa565b5b806105a257506000809054906101000a900460ff16155b6105f7576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252602e815260200180610ba6602e913960400191505060405180910390fd5b60008060019054906101000a900460ff161590508015610647576001600060016101000a81548160ff02191690831515021790555060016000806101000a81548160ff0219169083151502179055505b610650826109c1565b80156106715760008060016101000a81548160ff0219169083151502179055505b5050565b606660009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b6106a361050d565b610715576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260208152602001807f4f776e61626c653a2063616c6c6572206973206e6f7420746865206f776e657281525060200191505060405180910390fd5b61071d6104e3565b73ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff16141580156107a65750606660009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff1614155b610818576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252601c8152602001807f436c61696d61626c653a20696e76616c6964206e6577206f776e65720000000081525060200191505060405180910390fd5b80606660006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555050565b600073ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff1614156108e2576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401808060200182810382526026815260200180610b806026913960400191505060405180910390fd5b8073ffffffffffffffffffffffffffffffffffffffff16603360009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff167f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e060405160405180910390a380603360006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555050565b600033905090565b6000803090506000813b9050600081149250505090565b600060019054906101000a900460ff16806109e057506109df6109aa565b5b806109f757506000809054906101000a900460ff16155b610a4c576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252602e815260200180610ba6602e913960400191505060405180910390fd5b60008060019054906101000a900460ff161590508015610a9c576001600060016101000a81548160ff02191690831515021790555060016000806101000a81548160ff0219169083151502179055505b81603360006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550603360009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16600073ffffffffffffffffffffffffffffffffffffffff167f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e060405160405180910390a38015610b7b5760008060016101000a81548160ff0219169083151502179055505b505056fe4f776e61626c653a206e6577206f776e657220697320746865207a65726f2061646472657373436f6e747261637420696e7374616e63652068617320616c7265616479206265656e20696e697469616c697a6564436c61696d61626c653a2063616c6c6572206973206e6f74207468652070656e64696e67206f776e6572a265627a7a72315820358609594e8c88924aead5c6d84646d0529ea3cd48d7c189f4ca654b1275849864736f6c63430005110032";

export class Claimable__factory extends ContractFactory {
  constructor(signer?: Signer) {
    super(_abi, _bytecode, signer);
  }

  deploy(
    overrides?: Overrides & { from?: string | Promise<string> }
  ): Promise<Claimable> {
    return super.deploy(overrides || {}) as Promise<Claimable>;
  }
  getDeployTransaction(
    overrides?: Overrides & { from?: string | Promise<string> }
  ): TransactionRequest {
    return super.getDeployTransaction(overrides || {});
  }
  attach(address: string): Claimable {
    return super.attach(address) as Claimable;
  }
  connect(signer: Signer): Claimable__factory {
    return super.connect(signer) as Claimable__factory;
  }
  static readonly bytecode = _bytecode;
  static readonly abi = _abi;
  static createInterface(): ClaimableInterface {
    return new utils.Interface(_abi) as ClaimableInterface;
  }
  static connect(
    address: string,
    signerOrProvider: Signer | Provider
  ): Claimable {
    return new Contract(address, _abi, signerOrProvider) as Claimable;
  }
}
