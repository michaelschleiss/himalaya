# OAuth Wizard Interception Fix - COMPLETED

## Problem
When running `himalaya account auth gmail`, the system wizard was intercepting the command before the OAuth flow could execute. This happened because:

1. `HimalayaCommand::execute()` in src/cli.rs called `TomlConfig::from_paths_or_default()` for ALL account commands
2. This function triggers an interactive wizard if the config file doesn't exist
3. For the OAuth auth command, no existing config is needed - it creates one

## Solution
Modified `src/cli.rs` to check if the account subcommand is `Auth` and skip the wizard:

```rust
#[cfg(feature = "oauth2")]
let config = if matches!(cmd, AccountSubcommand::Auth(_)) {
    TomlConfig::from_default_paths().await.unwrap_or_default()
} else {
    TomlConfig::from_paths_or_default(config_paths).await?
};

#[cfg(not(feature = "oauth2"))]
let config = TomlConfig::from_paths_or_default(config_paths).await?;
```

### Key Changes:
- For OAuth auth command: Uses `from_default_paths()` (no wizard)
- For other account commands: Uses `from_paths_or_default()` (wizard enabled)
- Feature-gated to only apply when oauth2 feature is enabled

## Result
✅ `himalaya account auth gmail` now runs DIRECTLY without wizard interference
✅ Goes straight to OAuth setup prompts:
- Account name [default: gmail]:
- Please provide your OAuth 2.0 credentials:
- Client ID:
- Client Secret:
- Email address:

## Commit
Commit: 1862a14
Message: "fix: skip wizard interception for oauth auth command"

## Testing
Verified with simulated input - auth command executes without wizard intercepting, going straight to OAuth credential prompts.

## Next Steps
1. Test full OAuth Device Authorization Grant flow with real credentials
2. Verify tokens are stored correctly in keyring
3. Test IMAP/SMTP authentication with stored tokens
