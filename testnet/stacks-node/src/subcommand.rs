// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! Utilities and structs for subcommands part of the Stacks node executable.

use std::str::FromStr;

/// Subcommands available for running a Stacks node.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum StacksNodeSubcommand {
    /// Starts a Stacks node with a local Bitcoin regtest node as burnchain.
    StartRegtest,
    /// Starts a Stacks node with a local Bitcoin mocknet as burnchain.
    StartMocknet,
    /// Starts a Stacks node with the public Bitcoin testnet as burnchain.
    StartTestnet,
    /// Starts a Stacks node with the public Bitcoin mainnet as burnchain.
    StartMainnet,
    /// Starts a Stacks node with a supplied configuration file.
    Start,
    /// Validates a supplied config file.
    ValidateConfig,
    /// Shows the secret key of a burnchain signer created with a provided seed.
    ShowKeyForSeed,
    /// Shows the best chain tip for a given block height.
    ShowBestTip,
    /// Shows the amount spent by a miner at a given block height.
    ShowMinerSpendAmount,
    /// Shows the Stacks node version.
    ShowVersion,
    /// Shows the help.
    ShowHelp,
    /// Starts a Stacks node with a local regtest Bitcoin node as burnchain.
    #[deprecated = "Subcommand 'helium' has been deprecated for 'regtest'."]
    StartHelium,
}

impl FromStr for StacksNodeSubcommand {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "helium" => Ok(StacksNodeSubcommand::StartHelium),
            "regtest" => Ok(StacksNodeSubcommand::StartRegtest),
            "mocknet" => Ok(StacksNodeSubcommand::StartMocknet),
            "testnet" => Ok(StacksNodeSubcommand::StartTestnet),
            "mainnet" => Ok(StacksNodeSubcommand::StartMainnet),
            "check-config" => Ok(StacksNodeSubcommand::ValidateConfig),
            "start" => Ok(StacksNodeSubcommand::Start),
            "version" => Ok(StacksNodeSubcommand::ShowVersion),
            "key-for-seed" => Ok(StacksNodeSubcommand::ShowKeyForSeed),
            "pick-best-tip" => Ok(StacksNodeSubcommand::ShowBestTip),
            "get-spend-amount" => Ok(StacksNodeSubcommand::ShowMinerSpendAmount),
            _ => Ok(StacksNodeSubcommand::ShowHelp),
        }
    }
}
