/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */

import { Signer, utils, Contract, ContractFactory, Overrides } from "ethers";
import { Provider, TransactionRequest } from "@ethersproject/providers";
import type {
  ERC20WithPermit,
  ERC20WithPermitInterface,
} from "../ERC20WithPermit";

const _abi = [
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: "address",
        name: "owner",
        type: "address",
      },
      {
        indexed: true,
        internalType: "address",
        name: "spender",
        type: "address",
      },
      {
        indexed: false,
        internalType: "uint256",
        name: "value",
        type: "uint256",
      },
    ],
    name: "Approval",
    type: "event",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: "address",
        name: "from",
        type: "address",
      },
      {
        indexed: true,
        internalType: "address",
        name: "to",
        type: "address",
      },
      {
        indexed: false,
        internalType: "uint256",
        name: "value",
        type: "uint256",
      },
    ],
    name: "Transfer",
    type: "event",
  },
  {
    constant: true,
    inputs: [],
    name: "DOMAIN_SEPARATOR",
    outputs: [
      {
        internalType: "bytes32",
        name: "",
        type: "bytes32",
      },
    ],
    payable: false,
    stateMutability: "view",
    type: "function",
  },
  {
    constant: true,
    inputs: [],
    name: "PERMIT_TYPEHASH",
    outputs: [
      {
        internalType: "bytes32",
        name: "",
        type: "bytes32",
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
        name: "owner",
        type: "address",
      },
      {
        internalType: "address",
        name: "spender",
        type: "address",
      },
    ],
    name: "allowance",
    outputs: [
      {
        internalType: "uint256",
        name: "",
        type: "uint256",
      },
    ],
    payable: false,
    stateMutability: "view",
    type: "function",
  },
  {
    constant: false,
    inputs: [
      {
        internalType: "address",
        name: "spender",
        type: "address",
      },
      {
        internalType: "uint256",
        name: "amount",
        type: "uint256",
      },
    ],
    name: "approve",
    outputs: [
      {
        internalType: "bool",
        name: "",
        type: "bool",
      },
    ],
    payable: false,
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    constant: true,
    inputs: [
      {
        internalType: "address",
        name: "account",
        type: "address",
      },
    ],
    name: "balanceOf",
    outputs: [
      {
        internalType: "uint256",
        name: "",
        type: "uint256",
      },
    ],
    payable: false,
    stateMutability: "view",
    type: "function",
  },
  {
    constant: true,
    inputs: [],
    name: "decimals",
    outputs: [
      {
        internalType: "uint8",
        name: "",
        type: "uint8",
      },
    ],
    payable: false,
    stateMutability: "view",
    type: "function",
  },
  {
    constant: false,
    inputs: [
      {
        internalType: "address",
        name: "spender",
        type: "address",
      },
      {
        internalType: "uint256",
        name: "subtractedValue",
        type: "uint256",
      },
    ],
    name: "decreaseAllowance",
    outputs: [
      {
        internalType: "bool",
        name: "",
        type: "bool",
      },
    ],
    payable: false,
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    constant: false,
    inputs: [
      {
        internalType: "address",
        name: "spender",
        type: "address",
      },
      {
        internalType: "uint256",
        name: "addedValue",
        type: "uint256",
      },
    ],
    name: "increaseAllowance",
    outputs: [
      {
        internalType: "bool",
        name: "",
        type: "bool",
      },
    ],
    payable: false,
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    constant: false,
    inputs: [
      {
        internalType: "string",
        name: "name",
        type: "string",
      },
      {
        internalType: "string",
        name: "symbol",
        type: "string",
      },
      {
        internalType: "uint8",
        name: "decimals",
        type: "uint8",
      },
    ],
    name: "initialize",
    outputs: [],
    payable: false,
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    constant: false,
    inputs: [
      {
        internalType: "uint256",
        name: "_chainId",
        type: "uint256",
      },
      {
        internalType: "string",
        name: "_version",
        type: "string",
      },
      {
        internalType: "string",
        name: "_name",
        type: "string",
      },
      {
        internalType: "string",
        name: "_symbol",
        type: "string",
      },
      {
        internalType: "uint8",
        name: "_decimals",
        type: "uint8",
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
    name: "name",
    outputs: [
      {
        internalType: "string",
        name: "",
        type: "string",
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
        name: "",
        type: "address",
      },
    ],
    name: "nonces",
    outputs: [
      {
        internalType: "uint256",
        name: "",
        type: "uint256",
      },
    ],
    payable: false,
    stateMutability: "view",
    type: "function",
  },
  {
    constant: false,
    inputs: [
      {
        internalType: "address",
        name: "holder",
        type: "address",
      },
      {
        internalType: "address",
        name: "spender",
        type: "address",
      },
      {
        internalType: "uint256",
        name: "nonce",
        type: "uint256",
      },
      {
        internalType: "uint256",
        name: "expiry",
        type: "uint256",
      },
      {
        internalType: "bool",
        name: "allowed",
        type: "bool",
      },
      {
        internalType: "uint8",
        name: "v",
        type: "uint8",
      },
      {
        internalType: "bytes32",
        name: "r",
        type: "bytes32",
      },
      {
        internalType: "bytes32",
        name: "s",
        type: "bytes32",
      },
    ],
    name: "permit",
    outputs: [],
    payable: false,
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    constant: true,
    inputs: [],
    name: "symbol",
    outputs: [
      {
        internalType: "string",
        name: "",
        type: "string",
      },
    ],
    payable: false,
    stateMutability: "view",
    type: "function",
  },
  {
    constant: true,
    inputs: [],
    name: "totalSupply",
    outputs: [
      {
        internalType: "uint256",
        name: "",
        type: "uint256",
      },
    ],
    payable: false,
    stateMutability: "view",
    type: "function",
  },
  {
    constant: false,
    inputs: [
      {
        internalType: "address",
        name: "recipient",
        type: "address",
      },
      {
        internalType: "uint256",
        name: "amount",
        type: "uint256",
      },
    ],
    name: "transfer",
    outputs: [
      {
        internalType: "bool",
        name: "",
        type: "bool",
      },
    ],
    payable: false,
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    constant: false,
    inputs: [
      {
        internalType: "address",
        name: "sender",
        type: "address",
      },
      {
        internalType: "address",
        name: "recipient",
        type: "address",
      },
      {
        internalType: "uint256",
        name: "amount",
        type: "uint256",
      },
    ],
    name: "transferFrom",
    outputs: [
      {
        internalType: "bool",
        name: "",
        type: "bool",
      },
    ],
    payable: false,
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    constant: true,
    inputs: [],
    name: "version",
    outputs: [
      {
        internalType: "string",
        name: "",
        type: "string",
      },
    ],
    payable: false,
    stateMutability: "view",
    type: "function",
  },
];

const _bytecode =
  "0x6080604052612073806100136000396000f3fe608060405234801561001057600080fd5b50600436106101165760003560e01c806354fd4d50116100a25780638fcbaf0c116100715780638fcbaf0c1461080057806395d89b41146108a6578063a457c2d714610929578063a9059cbb1461098f578063dd62ed3e146109f557610116565b806354fd4d50146104cd5780635dca34521461055057806370a08231146107505780637ecebe00146107a857610116565b806323b872dd116100e957806323b872dd1461038157806330adf81f14610407578063313ce567146104255780633644e51514610449578063395093511461046757610116565b806306fdde031461011b578063095ea7b31461019e5780631624f6c61461020457806318160ddd14610363575b600080fd5b610123610a6d565b6040518080602001828103825283818151815260200191508051906020019080838360005b83811015610163578082015181840152602081019050610148565b50505050905090810190601f1680156101905780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b6101ea600480360360408110156101b457600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919080359060200190929190505050610b0f565b604051808215151515815260200191505060405180910390f35b6103616004803603606081101561021a57600080fd5b810190808035906020019064010000000081111561023757600080fd5b82018360208201111561024957600080fd5b8035906020019184600183028401116401000000008311171561026b57600080fd5b91908080601f016020809104026020016040519081016040528093929190818152602001838380828437600081840152601f19601f820116905080830192505050505050509192919290803590602001906401000000008111156102ce57600080fd5b8201836020820111156102e057600080fd5b8035906020019184600183028401116401000000008311171561030257600080fd5b91908080601f016020809104026020016040519081016040528093929190818152602001838380828437600081840152601f19601f820116905080830192505050505050509192919290803560ff169060200190929190505050610b2d565b005b61036b610c78565b6040518082815260200191505060405180910390f35b6103ed6004803603606081101561039757600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803573ffffffffffffffffffffffffffffffffffffffff16906020019092919080359060200190929190505050610c82565b604051808215151515815260200191505060405180910390f35b61040f610d5b565b6040518082815260200191505060405180910390f35b61042d610d82565b604051808260ff1660ff16815260200191505060405180910390f35b610451610d99565b6040518082815260200191505060405180910390f35b6104b36004803603604081101561047d57600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919080359060200190929190505050610d9f565b604051808215151515815260200191505060405180910390f35b6104d5610e52565b6040518080602001828103825283818151815260200191508051906020019080838360005b838110156105155780820151818401526020810190506104fa565b50505050905090810190601f1680156105425780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b61074e600480360360a081101561056657600080fd5b81019080803590602001909291908035906020019064010000000081111561058d57600080fd5b82018360208201111561059f57600080fd5b803590602001918460018302840111640100000000831117156105c157600080fd5b91908080601f016020809104026020016040519081016040528093929190818152602001838380828437600081840152601f19601f8201169050808301925050505050505091929192908035906020019064010000000081111561062457600080fd5b82018360208201111561063657600080fd5b8035906020019184600183028401116401000000008311171561065857600080fd5b91908080601f016020809104026020016040519081016040528093929190818152602001838380828437600081840152601f19601f820116905080830192505050505050509192919290803590602001906401000000008111156106bb57600080fd5b8201836020820111156106cd57600080fd5b803590602001918460018302840111640100000000831117156106ef57600080fd5b91908080601f016020809104026020016040519081016040528093929190818152602001838380828437600081840152601f19601f820116905080830192505050505050509192919290803560ff169060200190929190505050610ef0565b005b6107926004803603602081101561076657600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919050505061111e565b6040518082815260200191505060405180910390f35b6107ea600480360360208110156107be57600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050611167565b6040518082815260200191505060405180910390f35b6108a4600480360361010081101561081757600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803573ffffffffffffffffffffffffffffffffffffffff1690602001909291908035906020019092919080359060200190929190803515159060200190929190803560ff169060200190929190803590602001909291908035906020019092919050505061117f565b005b6108ae6115a5565b6040518080602001828103825283818151815260200191508051906020019080838360005b838110156108ee5780820151818401526020810190506108d3565b50505050905090810190601f16801561091b5780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b6109756004803603604081101561093f57600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919080359060200190929190505050611647565b604051808215151515815260200191505060405180910390f35b6109db600480360360408110156109a557600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919080359060200190929190505050611714565b604051808215151515815260200191505060405180910390f35b610a5760048036036040811015610a0b57600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050611732565b6040518082815260200191505060405180910390f35b606060688054600181600116156101000203166002900480601f016020809104026020016040519081016040528092919081815260200182805460018160011615610100020316600290048015610b055780601f10610ada57610100808354040283529160200191610b05565b820191906000526020600020905b815481529060010190602001808311610ae857829003601f168201915b5050505050905090565b6000610b23610b1c6117b9565b84846117c1565b6001905092915050565b600060019054906101000a900460ff1680610b4c5750610b4b6119b8565b5b80610b6357506000809054906101000a900460ff16155b610bb8576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252602e815260200180611f7d602e913960400191505060405180910390fd5b60008060019054906101000a900460ff161590508015610c08576001600060016101000a81548160ff02191690831515021790555060016000806101000a81548160ff0219169083151502179055505b8360689080519060200190610c1e929190611dd1565b508260699080519060200190610c35929190611dd1565b5081606a60006101000a81548160ff021916908360ff1602179055508015610c725760008060016101000a81548160ff0219169083151502179055505b50505050565b6000603554905090565b6000610c8f8484846119cf565b610d5084610c9b6117b9565b610d4b85604051806060016040528060288152602001611f5560289139603460008b73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000610d016117b9565b73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054611c899092919063ffffffff16565b6117c1565b600190509392505050565b7fea2aa0a1be11a07ed86d755c93467f4f82362b452371d1ba94d1715123511acb60001b81565b6000606a60009054906101000a900460ff16905090565b609f5481565b6000610e48610dac6117b9565b84610e438560346000610dbd6117b9565b73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008973ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054611d4990919063ffffffff16565b6117c1565b6001905092915050565b609e8054600181600116156101000203166002900480601f016020809104026020016040519081016040528092919081815260200182805460018160011615610100020316600290048015610ee85780601f10610ebd57610100808354040283529160200191610ee8565b820191906000526020600020905b815481529060010190602001808311610ecb57829003601f168201915b505050505081565b600060019054906101000a900460ff1680610f0f5750610f0e6119b8565b5b80610f2657506000809054906101000a900460ff16155b610f7b576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252602e815260200180611f7d602e913960400191505060405180910390fd5b60008060019054906101000a900460ff161590508015610fcb576001600060016101000a81548160ff02191690831515021790555060016000806101000a81548160ff0219169083151502179055505b610fd6848484610b2d565b84609e9080519060200190610fec929190611dd1565b506040518080611f03605291396052019050604051809103902061100e610a6d565b80519060200120609e60405180828054600181600116156101000203166002900480156110725780601f10611050576101008083540402835291820191611072565b820191906000526020600020905b81548152906001019060200180831161105e575b505091505060405180910390208830604051602001808681526020018581526020018481526020018381526020018273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019550505050505060405160208183030381529060405280519060200120609f8190555080156111165760008060016101000a81548160ff0219169083151502179055505b505050505050565b6000603360008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020549050919050565b609d6020528060005260406000206000915090505481565b6000609f547fea2aa0a1be11a07ed86d755c93467f4f82362b452371d1ba94d1715123511acb60001b8a8a8a8a8a604051602001808781526020018673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020018573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020018481526020018381526020018215151515815260200196505050505050506040516020818303038152906040528051906020012060405160200180807f190100000000000000000000000000000000000000000000000000000000000081525060020183815260200182815260200192505050604051602081830303815290604052805190602001209050600073ffffffffffffffffffffffffffffffffffffffff168973ffffffffffffffffffffffffffffffffffffffff16141561132f576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260268152602001806120196026913960400191505060405180910390fd5b60018185858560405160008152602001604052604051808581526020018460ff1660ff1681526020018381526020018281526020019450505050506020604051602081039080840390855afa15801561138c573d6000803e3d6000fd5b5050506020604051035173ffffffffffffffffffffffffffffffffffffffff168973ffffffffffffffffffffffffffffffffffffffff1614611436576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260208152602001807f455243323057697468526174653a20696e76616c6964207369676e617475726581525060200191505060405180910390fd5b60008614806114455750854211155b61149a576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401808060200182810382526021815260200180611ee26021913960400191505060405180910390fd5b609d60008a73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600081548092919060010191905055871461155c576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252601c8152602001807f455243323057697468526174653a20696e76616c6964206e6f6e63650000000081525060200191505060405180910390fd5b60008561156a57600061158c565b7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff5b90506115998a8a836117c1565b50505050505050505050565b606060698054600181600116156101000203166002900480601f01602080910402602001604051908101604052809291908181526020018280546001816001161561010002031660029004801561163d5780601f106116125761010080835404028352916020019161163d565b820191906000526020600020905b81548152906001019060200180831161162057829003601f168201915b5050505050905090565b600061170a6116546117b9565b8461170585604051806060016040528060258152602001611ff4602591396034600061167e6117b9565b73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008a73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054611c899092919063ffffffff16565b6117c1565b6001905092915050565b60006117286117216117b9565b84846119cf565b6001905092915050565b6000603460008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054905092915050565b600033905090565b600073ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff161415611847576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401808060200182810382526024815260200180611fd06024913960400191505060405180910390fd5b600073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff1614156118cd576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401808060200182810382526022815260200180611e9a6022913960400191505060405180910390fd5b80603460008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055508173ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff167f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925836040518082815260200191505060405180910390a3505050565b6000803090506000813b9050600081149250505090565b600073ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff161415611a55576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401808060200182810382526025815260200180611fab6025913960400191505060405180910390fd5b600073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff161415611adb576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401808060200182810382526023815260200180611e776023913960400191505060405180910390fd5b611b4781604051806060016040528060268152602001611ebc60269139603360008773ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054611c899092919063ffffffff16565b603360008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002081905550611bdc81603360008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054611d4990919063ffffffff16565b603360008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055508173ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef836040518082815260200191505060405180910390a3505050565b6000838311158290611d36576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825283818151815260200191508051906020019080838360005b83811015611cfb578082015181840152602081019050611ce0565b50505050905090810190601f168015611d285780820380516001836020036101000a031916815260200191505b509250505060405180910390fd5b5060008385039050809150509392505050565b600080828401905083811015611dc7576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252601b8152602001807f536166654d6174683a206164646974696f6e206f766572666c6f77000000000081525060200191505060405180910390fd5b8091505092915050565b828054600181600116156101000203166002900490600052602060002090601f016020900481019282601f10611e1257805160ff1916838001178555611e40565b82800160010185558215611e40579182015b82811115611e3f578251825591602001919060010190611e24565b5b509050611e4d9190611e51565b5090565b611e7391905b80821115611e6f576000816000905550600101611e57565b5090565b9056fe45524332303a207472616e7366657220746f20746865207a65726f206164647265737345524332303a20617070726f766520746f20746865207a65726f206164647265737345524332303a207472616e7366657220616d6f756e7420657863656564732062616c616e6365455243323057697468526174653a207065726d6974206861732065787069726564454950373132446f6d61696e28737472696e67206e616d652c737472696e672076657273696f6e2c75696e7432353620636861696e49642c6164647265737320766572696679696e67436f6e74726163742945524332303a207472616e7366657220616d6f756e74206578636565647320616c6c6f77616e6365436f6e747261637420696e7374616e63652068617320616c7265616479206265656e20696e697469616c697a656445524332303a207472616e736665722066726f6d20746865207a65726f206164647265737345524332303a20617070726f76652066726f6d20746865207a65726f206164647265737345524332303a2064656372656173656420616c6c6f77616e63652062656c6f77207a65726f455243323057697468526174653a2061646472657373206d757374206e6f7420626520307830a265627a7a7231582097310fb712098e0c74c95c5766679622d1a9605ce990a9b3126e196f1d067ea664736f6c63430005110032";

export class ERC20WithPermit__factory extends ContractFactory {
  constructor(signer?: Signer) {
    super(_abi, _bytecode, signer);
  }

  deploy(
    overrides?: Overrides & { from?: string | Promise<string> }
  ): Promise<ERC20WithPermit> {
    return super.deploy(overrides || {}) as Promise<ERC20WithPermit>;
  }
  getDeployTransaction(
    overrides?: Overrides & { from?: string | Promise<string> }
  ): TransactionRequest {
    return super.getDeployTransaction(overrides || {});
  }
  attach(address: string): ERC20WithPermit {
    return super.attach(address) as ERC20WithPermit;
  }
  connect(signer: Signer): ERC20WithPermit__factory {
    return super.connect(signer) as ERC20WithPermit__factory;
  }
  static readonly bytecode = _bytecode;
  static readonly abi = _abi;
  static createInterface(): ERC20WithPermitInterface {
    return new utils.Interface(_abi) as ERC20WithPermitInterface;
  }
  static connect(
    address: string,
    signerOrProvider: Signer | Provider
  ): ERC20WithPermit {
    return new Contract(address, _abi, signerOrProvider) as ERC20WithPermit;
  }
}
