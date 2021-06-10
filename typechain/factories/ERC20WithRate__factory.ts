/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */

import { Signer, utils, Contract, ContractFactory, Overrides } from "ethers";
import { Provider, TransactionRequest } from "@ethersproject/providers";
import type { ERC20WithRate, ERC20WithRateInterface } from "../ERC20WithRate";

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
        internalType: "uint256",
        name: "_rate",
        type: "uint256",
      },
    ],
    name: "LogRateChanged",
    type: "event",
  },
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
    name: "_rateScale",
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
    inputs: [
      {
        internalType: "address",
        name: "_account",
        type: "address",
      },
    ],
    name: "balanceOfUnderlying",
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
    constant: true,
    inputs: [],
    name: "exchangeRateCurrent",
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
    inputs: [
      {
        internalType: "uint256",
        name: "_amountUnderlying",
        type: "uint256",
      },
    ],
    name: "fromUnderlying",
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
        internalType: "address",
        name: "sender",
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
    constant: false,
    inputs: [
      {
        internalType: "address",
        name: "_nextOwner",
        type: "address",
      },
      {
        internalType: "uint256",
        name: "_initialRate",
        type: "uint256",
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
        internalType: "uint256",
        name: "_nextRate",
        type: "uint256",
      },
    ],
    name: "setExchangeRate",
    outputs: [],
    payable: false,
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    constant: true,
    inputs: [
      {
        internalType: "uint256",
        name: "_amount",
        type: "uint256",
      },
    ],
    name: "toUnderlying",
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
  "0x6080604052611c35806100136000396000f3fe608060405234801561001057600080fd5b506004361061012c5760003560e01c8063a173b2f6116100ad578063cd6dc68711610071578063cd6dc68714610555578063db068e0e146105a3578063dd62ed3e146105d1578063eb438fc214610649578063f2fde38b1461068b5761012c565b8063a173b2f6146103e5578063a457c2d714610427578063a9059cbb1461048d578063bd6d894d146104f3578063c4d66de8146105115761012c565b80633af9e669116100f45780633af9e669146102bf57806370a0823114610317578063715018a61461036f5780638da5cb5b146103795780638f32d59b146103c35761012c565b8063095ea7b31461013157806318160ddd1461019757806323b872dd146101b557806325e27ed81461023b5780633950935114610259575b600080fd5b61017d6004803603604081101561014757600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803590602001909291905050506106cf565b604051808215151515815260200191505060405180910390f35b61019f6106ed565b6040518082815260200191505060405180910390f35b610221600480360360608110156101cb57600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803590602001909291905050506106f7565b604051808215151515815260200191505060405180910390f35b6102436107d0565b6040518082815260200191505060405180910390f35b6102a56004803603604081101561026f57600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803590602001909291905050506107dc565b604051808215151515815260200191505060405180910390f35b610301600480360360208110156102d557600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919050505061088f565b6040518082815260200191505060405180910390f35b6103596004803603602081101561032d57600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff1690602001909291905050506108a9565b6040518082815260200191505060405180910390f35b6103776108f2565b005b610381610a2d565b604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b6103cb610a57565b604051808215151515815260200191505060405180910390f35b610411600480360360208110156103fb57600080fd5b8101908080359060200190929190505050610ab6565b6040518082815260200191505060405180910390f35b6104736004803603604081101561043d57600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919080359060200190929190505050610aee565b604051808215151515815260200191505060405180910390f35b6104d9600480360360408110156104a357600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919080359060200190929190505050610bbb565b604051808215151515815260200191505060405180910390f35b6104fb610bd9565b6040518082815260200191505060405180910390f35b6105536004803603602081101561052757600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610c3e565b005b6105a16004803603604081101561056b57600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919080359060200190929190505050610dfc565b005b6105cf600480360360208110156105b957600080fd5b8101908080359060200190929190505050610f0f565b005b610633600480360360408110156105e757600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610f95565b6040518082815260200191505060405180910390f35b6106756004803603602081101561065f57600080fd5b810190808035906020019092919050505061101c565b6040518082815260200191505060405180910390f35b6106cd600480360360208110156106a157600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050611054565b005b60006106e36106dc6110da565b84846110e2565b6001905092915050565b6000606854905090565b60006107048484846112d9565b6107c5846107106110da565b6107c085604051806060016040528060288152602001611b1060289139606760008b73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060006107766110da565b73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020546115939092919063ffffffff16565b6110e2565b600190509392505050565b670de0b6b3a764000081565b60006108856107e96110da565b8461088085606760006107fa6110da565b73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008973ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205461165390919063ffffffff16565b6110e2565b6001905092915050565b60006108a261089d836108a9565b61101c565b9050919050565b6000606660008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020549050919050565b6108fa610a57565b61096c576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260208152602001807f4f776e61626c653a2063616c6c6572206973206e6f7420746865206f776e657281525060200191505060405180910390fd5b600073ffffffffffffffffffffffffffffffffffffffff16603360009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff167f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e060405160405180910390a36000603360006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550565b6000603360009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16905090565b6000603360009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16610a9a6110da565b73ffffffffffffffffffffffffffffffffffffffff1614905090565b6000610ae7609b54610ad9670de0b6b3a7640000856116db90919063ffffffff16565b61176190919063ffffffff16565b9050919050565b6000610bb1610afb6110da565b84610bac85604051806060016040528060258152602001611bdc6025913960676000610b256110da565b73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008a73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020546115939092919063ffffffff16565b6110e2565b6001905092915050565b6000610bcf610bc86110da565b84846112d9565b6001905092915050565b600080609b541415610c36576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252602c815260200180611a9d602c913960400191505060405180910390fd5b609b54905090565b600060019054906101000a900460ff1680610c5d5750610c5c6117ab565b5b80610c7457506000809054906101000a900460ff16155b610cc9576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252602e815260200180611b38602e913960400191505060405180910390fd5b60008060019054906101000a900460ff161590508015610d19576001600060016101000a81548160ff02191690831515021790555060016000806101000a81548160ff0219169083151502179055505b81603360006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550603360009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16600073ffffffffffffffffffffffffffffffffffffffff167f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e060405160405180910390a38015610df85760008060016101000a81548160ff0219169083151502179055505b5050565b600060019054906101000a900460ff1680610e1b5750610e1a6117ab565b5b80610e3257506000809054906101000a900460ff16155b610e87576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252602e815260200180611b38602e913960400191505060405180910390fd5b60008060019054906101000a900460ff161590508015610ed7576001600060016101000a81548160ff02191690831515021790555060016000806101000a81548160ff0219169083151502179055505b610ee083610c3e565b610ee9826117c2565b8015610f0a5760008060016101000a81548160ff0219169083151502179055505b505050565b610f17610a57565b610f89576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260208152602001807f4f776e61626c653a2063616c6c6572206973206e6f7420746865206f776e657281525060200191505060405180910390fd5b610f92816117c2565b50565b6000606760008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054905092915050565b600061104d670de0b6b3a764000061103f609b54856116db90919063ffffffff16565b61176190919063ffffffff16565b9050919050565b61105c610a57565b6110ce576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260208152602001807f4f776e61626c653a2063616c6c6572206973206e6f7420746865206f776e657281525060200191505060405180910390fd5b6110d781611825565b50565b600033905090565b600073ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff161415611168576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401808060200182810382526024815260200180611b8b6024913960400191505060405180910390fd5b600073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff1614156111ee576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401808060200182810382526022815260200180611a7b6022913960400191505060405180910390fd5b80606760008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055508173ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff167f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925836040518082815260200191505060405180910390a3505050565b600073ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff16141561135f576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401808060200182810382526025815260200180611b666025913960400191505060405180910390fd5b600073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff1614156113e5576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401808060200182810382526023815260200180611a326023913960400191505060405180910390fd5b61145181604051806060016040528060268152602001611ac960269139606660008773ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020546115939092919063ffffffff16565b606660008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055506114e681606660008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205461165390919063ffffffff16565b606660008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055508173ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef836040518082815260200191505060405180910390a3505050565b6000838311158290611640576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825283818151815260200191508051906020019080838360005b838110156116055780820151818401526020810190506115ea565b50505050905090810190601f1680156116325780820380516001836020036101000a031916815260200191505b509250505060405180910390fd5b5060008385039050809150509392505050565b6000808284019050838110156116d1576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252601b8152602001807f536166654d6174683a206164646974696f6e206f766572666c6f77000000000081525060200191505060405180910390fd5b8091505092915050565b6000808314156116ee576000905061175b565b60008284029050828482816116ff57fe5b0414611756576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401808060200182810382526021815260200180611aef6021913960400191505060405180910390fd5b809150505b92915050565b60006117a383836040518060400160405280601a81526020017f536166654d6174683a206469766973696f6e206279207a65726f00000000000081525061196b565b905092915050565b6000803090506000813b9050600081149250505090565b6000811161181b576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252602d815260200180611baf602d913960400191505060405180910390fd5b80609b8190555050565b600073ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff1614156118ab576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401808060200182810382526026815260200180611a556026913960400191505060405180910390fd5b8073ffffffffffffffffffffffffffffffffffffffff16603360009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff167f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e060405160405180910390a380603360006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555050565b60008083118290611a17576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825283818151815260200191508051906020019080838360005b838110156119dc5780820151818401526020810190506119c1565b50505050905090810190601f168015611a095780820380516001836020036101000a031916815260200191505b509250505060405180910390fd5b506000838581611a2357fe5b04905080915050939250505056fe45524332303a207472616e7366657220746f20746865207a65726f20616464726573734f776e61626c653a206e6577206f776e657220697320746865207a65726f206164647265737345524332303a20617070726f766520746f20746865207a65726f2061646472657373455243323057697468526174653a207261746520686173206e6f74206265656e20696e697469616c697a656445524332303a207472616e7366657220616d6f756e7420657863656564732062616c616e6365536166654d6174683a206d756c7469706c69636174696f6e206f766572666c6f7745524332303a207472616e7366657220616d6f756e74206578636565647320616c6c6f77616e6365436f6e747261637420696e7374616e63652068617320616c7265616479206265656e20696e697469616c697a656445524332303a207472616e736665722066726f6d20746865207a65726f206164647265737345524332303a20617070726f76652066726f6d20746865207a65726f2061646472657373455243323057697468526174653a2072617465206d7573742062652067726561746572207468616e207a65726f45524332303a2064656372656173656420616c6c6f77616e63652062656c6f77207a65726fa265627a7a72315820543b610a2c0349c80fa323b8027181af079312bdc94b4af592351909b3478eb664736f6c63430005110032";

export class ERC20WithRate__factory extends ContractFactory {
  constructor(signer?: Signer) {
    super(_abi, _bytecode, signer);
  }

  deploy(
    overrides?: Overrides & { from?: string | Promise<string> }
  ): Promise<ERC20WithRate> {
    return super.deploy(overrides || {}) as Promise<ERC20WithRate>;
  }
  getDeployTransaction(
    overrides?: Overrides & { from?: string | Promise<string> }
  ): TransactionRequest {
    return super.getDeployTransaction(overrides || {});
  }
  attach(address: string): ERC20WithRate {
    return super.attach(address) as ERC20WithRate;
  }
  connect(signer: Signer): ERC20WithRate__factory {
    return super.connect(signer) as ERC20WithRate__factory;
  }
  static readonly bytecode = _bytecode;
  static readonly abi = _abi;
  static createInterface(): ERC20WithRateInterface {
    return new utils.Interface(_abi) as ERC20WithRateInterface;
  }
  static connect(
    address: string,
    signerOrProvider: Signer | Provider
  ): ERC20WithRate {
    return new Contract(address, _abi, signerOrProvider) as ERC20WithRate;
  }
}
