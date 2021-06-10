/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */

import { Signer, utils, Contract, ContractFactory, Overrides } from "ethers";
import { Provider, TransactionRequest } from "@ethersproject/providers";
import type {
  InitializableUpgradeabilityProxy,
  InitializableUpgradeabilityProxyInterface,
} from "../InitializableUpgradeabilityProxy";

const _abi = [
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: "address",
        name: "implementation",
        type: "address",
      },
    ],
    name: "Upgraded",
    type: "event",
  },
  {
    payable: true,
    stateMutability: "payable",
    type: "fallback",
  },
  {
    constant: false,
    inputs: [
      {
        internalType: "address",
        name: "_logic",
        type: "address",
      },
      {
        internalType: "bytes",
        name: "_data",
        type: "bytes",
      },
    ],
    name: "initialize",
    outputs: [],
    payable: true,
    stateMutability: "payable",
    type: "function",
  },
];

const _bytecode =
  "0x608060405234801561001057600080fd5b50610409806100206000396000f3fe60806040526004361061001e5760003560e01c8063d1f5789414610028575b610026610103565b005b6101016004803603604081101561003e57600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff1690602001909291908035906020019064010000000081111561007b57600080fd5b82018360208201111561008d57600080fd5b803590602001918460018302840111640100000000831117156100af57600080fd5b91908080601f016020809104026020016040519081016040528093929190818152602001838380828437600081840152601f19601f82011690508083019250505050505050919291929050505061011d565b005b61010b6102a0565b61011b6101166102a2565b6102d3565b565b600073ffffffffffffffffffffffffffffffffffffffff1661013d6102a2565b73ffffffffffffffffffffffffffffffffffffffff161461015d57600080fd5b600160405180807f656970313936372e70726f78792e696d706c656d656e746174696f6e00000000815250601c019050604051809103902060001c0360001b7f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc60001b146101c757fe5b6101d0826102f9565b60008151111561029c5760008273ffffffffffffffffffffffffffffffffffffffff16826040518082805190602001908083835b602083106102275780518252602082019150602081019050602083039250610204565b6001836020036101000a038019825116818451168082178552505050505050905001915050600060405180830381855af49150503d8060008114610287576040519150601f19603f3d011682016040523d82523d6000602084013e61028c565b606091505b505090508061029a57600080fd5b505b5050565b565b6000807f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc60001b9050805491505090565b3660008037600080366000845af43d6000803e80600081146102f4573d6000f35b3d6000fd5b61030281610386565b610357576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252603b81526020018061039a603b913960400191505060405180910390fd5b60007f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc60001b90508181555050565b600080823b90506000811191505091905056fe43616e6e6f742073657420612070726f787920696d706c656d656e746174696f6e20746f2061206e6f6e2d636f6e74726163742061646472657373a265627a7a72315820563b402febf354cb414338b00fecbdaae3058f3d7e70aa93126102732f0ce25764736f6c63430005110032";

export class InitializableUpgradeabilityProxy__factory extends ContractFactory {
  constructor(signer?: Signer) {
    super(_abi, _bytecode, signer);
  }

  deploy(
    overrides?: Overrides & { from?: string | Promise<string> }
  ): Promise<InitializableUpgradeabilityProxy> {
    return super.deploy(
      overrides || {}
    ) as Promise<InitializableUpgradeabilityProxy>;
  }
  getDeployTransaction(
    overrides?: Overrides & { from?: string | Promise<string> }
  ): TransactionRequest {
    return super.getDeployTransaction(overrides || {});
  }
  attach(address: string): InitializableUpgradeabilityProxy {
    return super.attach(address) as InitializableUpgradeabilityProxy;
  }
  connect(signer: Signer): InitializableUpgradeabilityProxy__factory {
    return super.connect(signer) as InitializableUpgradeabilityProxy__factory;
  }
  static readonly bytecode = _bytecode;
  static readonly abi = _abi;
  static createInterface(): InitializableUpgradeabilityProxyInterface {
    return new utils.Interface(
      _abi
    ) as InitializableUpgradeabilityProxyInterface;
  }
  static connect(
    address: string,
    signerOrProvider: Signer | Provider
  ): InitializableUpgradeabilityProxy {
    return new Contract(
      address,
      _abi,
      signerOrProvider
    ) as InitializableUpgradeabilityProxy;
  }
}
