# Releasing Cert Lab

Release Please opens and updates a release PR from Conventional Commits on `main`. It maintains `version.txt`, `CHANGELOG.md`, and `.release-please-manifest.json`. Merging that PR creates the version tag and publishes the GitHub Release with generated notes. The same workflow run then tests, build a universal app, sign with Developer ID, notarize, staple, and check Gatekeeper before attaching the ZIP and `SHA256SUMS.txt`. The release page is visible while its downloads are still building.

## Create the release environment

The Apple secrets live in a GitHub environment named `release`, so only the signing job can read them, and only when it runs from `main`. Without this, anyone with write access could read them by running a modified workflow from another branch.

In [Settings → Environments](https://github.com/viaductindustries/cert-lab/settings/environments), create an environment named `release`:

- Under **Deployment branches and tags**, choose **Selected branches and tags** and add the branch rule `main`. Release builds always run from `main`, including manual rebuilds; the tag is only checked out.
- Optionally, add **Required reviewers** so each signed build waits for approval. Leave **Allow administrators to bypass configured protection rules** off if you want the rules to apply to everyone.

## Upload the credentials

Add the three secrets below as **environment secrets** in the `release` environment, not as repository secrets. Add the two identifiers as repository variables in [Settings → Secrets and variables → Actions](https://github.com/viaductindustries/cert-lab/settings/variables/actions), using **New repository variable**. They aren't secret, but they can live in the environment too. GitHub accepts text here; use the commands below to prepare the two files. Do not commit these files or paste their contents into issues or chat.

| `release` environment secret | Value to upload |
|---|---|
| `APPLE_CERTIFICATE_BASE64` | Base64 of a `.p12` containing exactly one valid **Developer ID Application** certificate and its private key |
| `APPLE_CERTIFICATE_PASSWORD` | The password chosen when exporting that `.p12` |
| `APPLE_API_PRIVATE_KEY_BASE64` | Base64 of the complete downloaded `.p8` file |

| Repository variable | Value |
|---|---|
| `APPLE_API_KEY_ID` | The Key ID of the App Store Connect **team** API key |
| `APPLE_API_ISSUER_ID` | The Issuer ID shown on the App Store Connect team API keys page (not the Apple Developer Team ID) |

### Developer ID signing certificate

Use the Viaduct Industries Developer ID Application identity already on the maintainer's Mac, if it is valid. In **Keychain Access → My Certificates**, find `Developer ID Application: …`, expand it to confirm its private key is present, and export the identity as a password-protected `.p12`. A certificate downloaded as `.cer` alone does not contain the private key and is insufficient.

If a new identity is needed, create a **Developer ID Application** certificate through [Apple Developer Certificates](https://developer.apple.com/account/resources/certificates/list), using the account with the necessary permissions. This requires an active Apple Developer Program membership. Do not use Developer ID Installer, Apple Development, or an App Store distribution certificate.

Copy the exported file as base64, then paste it into `APPLE_CERTIFICATE_BASE64`:

```sh
base64 -i /path/to/DeveloperIDApplication.p12 | pbcopy
```

Save its export password separately as `APPLE_CERTIFICATE_PASSWORD`. The workflow generates its own temporary keychain password; no keychain-password secret is needed.

### Apple notarization API key

In [App Store Connect → Users and Access → Integrations](https://appstoreconnect.apple.com/access/integrations/api), create a **Team API Key** with **Developer** access or higher. An account administrator may need to enable API access or create the key. Use the same Apple Developer organization as the signing identity. This workflow uses team keys with an issuer; individual keys are not supported.

Save the **Key ID** and **Issuer ID** as the repository variables above, then download the private key (`AuthKey_….p8`). Apple only allows the private key to be downloaded once, so retain a secure backup. Encode the complete file as a single line for `APPLE_API_PRIVATE_KEY_BASE64`:

```sh
base64 -i /path/to/AuthKey_YOURKEYID.p8 | tr -d '\r\n' | pbcopy
```

You can store this same single-line value in a concealed 1Password Password field and paste it directly into the environment secret. The workflow decodes it into a temporary `.p8` file before calling Apple. Base64 is encoding, not encryption.

No Apple ID password, app-specific password, or provisioning profile is needed. The upload job uses GitHub's automatic `GITHUB_TOKEN` with `contents: write`; test and signing jobs have read-only repository permissions.

The implementation follows [GitHub's certificate import guidance](https://docs.github.com/en/actions/how-tos/deploy/deploy-to-third-party-platforms/sign-xcode-applications) and [Apple's notarization workflow](https://developer.apple.com/documentation/security/customizing-the-notarization-workflow). Credentials are written with private permissions to temporary storage and removed on exit; use GitHub-hosted runners for this workflow.

## Configure Homebrew publishing

After the notarized downloads are uploaded, the release workflow calls the pinned reusable workflow in [viaductindustries/homebrew-tap](https://github.com/viaductindustries/homebrew-tap). It verifies the release asset, computes its SHA-256, and opens a PR updating the `cert-lab` cask (or creating it for the first release). A maintainer reviews the installation checks and merges the PR before users can get the update through Homebrew.

Follow the tap's [publisher setup instructions](https://github.com/viaductindustries/homebrew-tap/blob/main/PUBLISHING.md#first-time-github-setup). The GitHub App needs **Contents** and **Pull requests** read/write permissions and should be installed only on `homebrew-tap`. Make these Actions settings available to **cert-lab**, either directly or through organization settings restricted to approved source repositories:

| Setting | Type | Value |
|---|---|---|
| `HOMEBREW_APP_CLIENT_ID` | Variable | The publisher GitHub App's Client ID |
| `HOMEBREW_APP_PRIVATE_KEY` | Secret | The complete GitHub App private key PEM, including header, footer and line breaks; not base64 |

The release workflow passes the private key to the tap job. The tap workflow can't read environment secrets, so this key stays a repository (or organization) secret; at worst it can open PRs on the tap, which a maintainer reviews. Apple credentials are not passed to the tap workflow. The tap generates a short-lived token scoped to its own repository; Cert Lab's automatic `GITHUB_TOKEN` cannot write to the other repository.

If the tap job fails, fix its credentials or reported issue and choose **Re-run failed jobs** on the original run. Do not rerun successful signing and upload jobs: the published downloads are immutable. A failed tap update does not invalidate the published app release.

## Set up the Release Please app

Release Please acts as a GitHub App rather than with `GITHUB_TOKEN`, because GitHub doesn't run pull-request CI for PRs opened or updated with `GITHUB_TOKEN`. With the app, release PRs get CI like any other PR. Each run creates a token that lasts an hour and can only reach this repository.

1. [Register the app](https://github.com/organizations/viaductindustries/settings/apps/new?name=Viaduct%20Release%20Please&description=Opens%20release%20PRs%20and%20publishes%20releases%20with%20Release%20Please.&url=https%3A%2F%2Fgithub.com%2Fviaductindustries%2Fcert-lab&public=false&webhook_active=false&contents=write&issues=write&pull_requests=write). The link fills in a private app with webhooks off and **Contents**, **Issues** and **Pull requests** read/write permissions. Nothing else is needed. The name must be unique on GitHub, so change it if it's taken.
2. On the app's page, choose **Install App** and install it on `viaductindustries`, with **Only select repositories** set to `cert-lab`.
3. Under **Private keys**, choose **Generate a private key**. Keep a copy in 1Password and delete the downloaded file afterwards.
4. In [Settings → Environments](https://github.com/viaductindustries/cert-lab/settings/environments), open the `release-please` environment (create it if needed, allowing only the `main` branch, as for `release`) and add:

| `release-please` environment setting | Type | Value |
|---|---|---|
| `RELEASE_PLEASE_APP_CLIENT_ID` | Variable | The app's Client ID, from its **General** page |
| `RELEASE_PLEASE_APP_PRIVATE_KEY` | Secret | The complete private key PEM, including header, footer and line breaks; not base64 |

For example, `gh secret set RELEASE_PLEASE_APP_PRIVATE_KEY --env release-please < ~/Downloads/viaduct-release-please.*.private-key.pem`.

The workflow's own `GITHUB_TOKEN` has no permissions in the Release Please job, and **Allow GitHub Actions to create and approve pull requests** isn't needed. The release build runs as later jobs in the same workflow when Release Please reports a new release; it doesn't depend on a tag-push or release event triggering another workflow. It isn't a separate reusable workflow either, because GitHub leaves environment secrets empty in a called workflow unless the caller uses `secrets: inherit` ([actions/runner#4453](https://github.com/actions/runner/issues/4453)). See the [Release Please action's credential guidance](https://github.com/googleapis/release-please-action#github-credentials).

## Make a release

1. Create the `release` environment, add the three Apple secrets to it and the two Apple variables above, configure the Homebrew publisher credentials, set up the Release Please app, and merge these workflow changes into `main`.
2. Merge changes using Conventional Commits. `fix:` and `perf:` produce patch releases, `feat:` produces minor releases, and breaking changes (`!` or a `BREAKING CHANGE:` footer) produce major releases. All supported Conventional Commit types can trigger a release: `docs:`, `test:`, `ci:`, `build:`, `chore:`, `refactor:`, `style:` and `revert:` also produce patch releases. Continue using Conventional Commit messages; unstructured commit messages are not supported. Merging the generated release PR remains the step that publishes a release.
3. Release Please opens or updates a release PR containing the proposed version and changelog. Review it and check CI. The initial release is configured as **1.0.0**; the empty initial manifest means no previous release is recorded.
4. Merge the release PR when ready. Release Please creates the `vX.Y.Z` tag and publishes the release notes automatically, then starts the signed build. You do not need to edit `version.txt`, push tags, or create releases yourself.
5. Follow the [Release workflow](https://github.com/viaductindustries/cert-lab/actions/workflows/release.yml). When its build and upload jobs succeed, the [GitHub Release](https://github.com/viaductindustries/cert-lab/releases) contains the notarized universal ZIP and checksums. Download the app and verify the interactive 1Password approval experience.
6. Review the automatically opened PR in [homebrew-tap](https://github.com/viaductindustries/homebrew-tap/pulls). Merge it once the tap's validation and installation checks pass. Users can then run `brew update` and `brew upgrade --cask cert-lab`.

`version.txt` remains the build input, but Release Please owns its updates. `.release-please-manifest.json` tracks the released version; `release-please-config.json` selects the `simple` strategy. Numeric `vX.Y.Z` releases are supported; prerelease suffixes are not currently supported by the app build.

For a failed signing/build run, choose **Re-run failed jobs** on the original run, preserving the successful Release Please job's outputs. Rerunning the whole workflow after it has already created a release may report no new release and skip the build. To explicitly rebuild an existing release, run the **Release** workflow on `main` and enter its tag, or use the command below. Running it without a tag runs Release Please instead.

```sh
gh workflow run release.yml --ref main -f tag=v1.0.0
```

The build always checks out the requested tag and checks that it matches `version.txt`. The release must already exist. Upload retries skip byte-identical assets and refuse to overwrite different published assets. A fresh notarized build may differ because of signing timestamps; if downloads are already published, make a new release rather than replacing them. Never move a published tag.

Ordinary CI requires no Apple secrets and uploads an ad-hoc-signed universal development ZIP for 14 days; those artifacts are not notarized distribution downloads.

## Troubleshooting

- **Release Please fails to create a token:** check that the app is installed on `cert-lab` and that the client ID and private key are in the `release-please` environment, not the repository. A deleted private key must be replaced.
- **Release PR cannot be created or updated:** check that the app still has **Contents**, **Issues** and **Pull requests** read/write permissions, and that any permission change has been accepted on the installation.
- **Release has no downloads yet:** check the Release workflow run. Release notes are published before signing starts; if a later step fails, retry the failed build as described above.
- **Missing required environment variable:** check the three secrets in the `release` environment and the two variables above. The key and issuer IDs are read from `vars`, not `secrets`. Repository secrets with the same names aren't used. If the job's log shows the secrets as empty while the variables are set, check that the signing job is still in `release.yml` itself and not moved into a reusable workflow.
- **Branch is not allowed to deploy to release:** the build ran from a branch other than `main`. Rebuild with `--ref main`; the tag is passed separately.
- **No valid Developer ID Application identity:** re-export the certificate together with its private key. Check expiration and the `.p12` password. Only include one signing identity.
- **Apple authentication failure:** check the team API key, issuer UUID, Key ID and base64 encoding of the complete `.p8` file. A revoked key must be replaced.
- **Notarization rejected:** download the run's `notarization` artifact for Apple's `result.json` and `log.json`. Release assets are not uploaded when signing, notarization, stapling or Gatekeeper verification fails.
- **Notarization timeout:** the submission may still be processing at Apple. Its ID is recorded in the log and result artifact. Check Apple's service status and rerun when ready; a rerun makes a new submission.
- **Release permission failure:** check organization policies allow this repository's workflow `GITHUB_TOKEN` to write release contents. No personal token should be necessary.

The app remains unsandboxed and requires no entitlements. Developer ID signing adds the hardened runtime and secure timestamp. The bundle identifier remains `local.CertLab` so existing installations retain their identity. Source builds with `scripts/build-app.sh --install` remain ad-hoc signed.
