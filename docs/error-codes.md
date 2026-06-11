# Truthlinked Error Codes

## RPC Error Codes (Exact Match)

- 1001: account_id must be hex
- 1002: account_id must be 32 bytes (64 hex chars)
- 1003: account_id must be 64 hex chars
- 1004: Invalid account_id format (must be 32-byte hex)
- 1005: pubkey must be hex
- 1006: pubkey must be 1952 bytes (Dilithium, 3904 hex chars)
- 1007: cell_id must be hex
- 1008: cell_id must be 32 bytes (64 hex chars)
- 1009: cell_id and account_id must be 32 bytes each
- 1010: proposal_id must be hex
- 1011: proposal_id must be 32 bytes (64 hex chars)
- 1012: nft_id must be hex
- 1013: nft_id must be 32 bytes (64 hex chars)
- 1014: owner must be hex
- 1015: owner must be 32 bytes (64 hex chars)
- 1201: resolve only supports .tl names; use /search for hashes or IDs
- 1202: name expired
- 1203: name not found
- 4001: Storage not initialized

## RPC Error Codes (Rule Match)

- 4003: prefix match -> Failed to deserialize transaction:.
- 4004: prefix match -> Failed to load transaction history:.
- 4002: contains match -> Node is syncing; try again later.
- 4101: contains match -> Direct calls to MCP tools are not permitted.
- 4102: contains match -> McpToolCall requires action_log_id.

## Axiom VM Error Codes

- 2000: UsdcError::UnknownSelector
- 2001: UsdcError::NotOwner
- 2002: UsdcError::AlreadyInitialized
- 2003: UsdcError::NotInitialized
- 2004: UsdcError::NotMintAuthority
- 2005: UsdcError::NotFreezeAuthority
- 2006: UsdcError::InvalidFrom
- 2007: UsdcError::InvalidAmount
- 2008: UsdcError::MissingParam
- 2100: UsdtError::UnknownSelector
- 2101: UsdtError::NotOwner
- 2102: UsdtError::AlreadyInitialized
- 2103: UsdtError::NotInitialized
- 2104: UsdtError::NotMintAuthority
- 2105: UsdtError::NotFreezeAuthority
- 2106: UsdtError::InvalidFrom
- 2200: StakingError::UnknownSelector
- 2201: StakingError::BadCalldata
- 2202: StakingError::InvalidPubkey
- 2203: StakingError::Unauthorized
- 2204: StakingError::ZeroAmount
- 2300: GovError::UnknownSelector
- 2301: GovError::BadCalldata
- 2302: GovError::InvalidPubkey
- 2303: GovError::Unauthorized
- 2304: GovError::ProposalExists
- 2305: GovError::ProposalMissing
- 2306: GovError::VotingClosed
- 2307: GovError::VotingOpen
- 2308: GovError::Timelock
- 2309: GovError::AlreadyVoted
- 2310: GovError::QuorumNotMet
- 2311: GovError::ZeroStake
- 2400: TreasuryError::UnknownSelector
- 2401: TreasuryError::BadCalldata
- 2402: TreasuryError::InvalidBucket
- 2403: TreasuryError::ZeroAmount
- 2404: TreasuryError::ProposalExists
- 2405: TreasuryError::ProposalMissing
- 2406: TreasuryError::VotingClosed
- 2407: TreasuryError::VotingOpen
- 2408: TreasuryError::Timelock
- 2409: TreasuryError::AlreadyVoted
- 2410: TreasuryError::QuorumNotMet
- 2411: TreasuryError::ZeroStake
- 2412: TreasuryError::InsufficientBucket
- 2500: NameRegistryError::UnknownSelector
- 2501: NameRegistryError::BadCalldata
- 2600: TokenGovError::UnknownSelector
- 2601: TokenGovError::BadCalldata
- 2700: OracleGovError::UnknownSelector
- 2701: OracleGovError::BadCalldata
- 2800: PolicyError::BadCalldata
- 2801: PolicyError::Unauthorized
- 2802: PolicyError::Suspended
- 2803: PolicyError::ToolDenied
- 2804: PolicyError::RateLimited
- 2805: PolicyError::SpendPerTxExceeded
- 2806: PolicyError::SpendEpochExceeded
- 2807: PolicyError::HitlRequired
- 2900: VetrthError::UnknownSelector
- 2901: VetrthError::BadCalldata
- 2902: VetrthError::Unauthorized
- 2903: VetrthError::ZeroAmount
- 2904: VetrthError::InvalidLockDuration
- 2905: VetrthError::PositionMissing
- 2906: VetrthError::NotMatured
- 2907: VetrthError::VeBalanceZero

## Fallback Hash Rule

If an error string is not in the explicit map and not an Error code: X, a stable code is derived as blake3(error_bytes)[0..4] as u32 & 0x7fffffff.
