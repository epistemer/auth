# API review for v0.1.0 (M6.2)

Every exported identifier of `auth`, `auth/access`, `auth/authtest` and
`authschema`, as `go doc -all` lists them on 2026-11-16, against
[interface.md](interface.md) §4 and the rules it serves. "Checked" names a
test that pins it down. Reviewed by Claude; the method was a mechanical diff
of `go doc -all` against §4's declarations, then each field list and the
§4.6 and §4.8 tables by hand.

## What the app provides (§4.1)

| Identifier | Interface | Checked |
|---|---|---|
| `UserID` | opaque, 1 to 64 bytes, no zero byte | `TestUserIDs`, `TestDirectoryAnswersForTheID` |
| `User` (`ID`, `Name`, `Disabled`) | as §4.1; a disabled user may not sign in | `TestDisabled`, `TestDisabledAtFinish`, `TestDisabledAnswersAlike`, `TestAcceptDisabled` |
| `Channel`, `ChannelEmail`, `ChannelSMS` | as §4.1 | `TestOneAddressOneFactor`, `TestCodeAsSecondProof` |
| `Directory`, `ErrNoUser` | `Find`, `Get`, `Address`; `ErrNoUser` is private | `TestEnumeration`, `TestDirectoryAnswersForTheID` |
| `MessageKind` and its eight constants, `Message`, `Sender` | as §4.1 | `TestCodeAsSecondProof`, `TestRecoverByLink`, `TestInviteAccept`, `TestFailedSendRefunded` |
| `Claimer` | claims on access tokens | `TestBearerSignIn`, `TestRefresh`, `TestRefreshReuseClaimerDown` |
| `Recorder`, `Event` | §5.11: one event per decision, no secret in any | `TestEventsHoldNoSecret`, `TestSessionEndedEvents`, `TestBearerNoSecrets` |
| `Client` | as seen when a session was made | `TestLoadClient`; `examples/shop` `TestAPI` |
| `Policy` (`AllowUnverified`, `TrustDevices`) | as §4.1; the default is `TrustDevices` alone | `TestCannotVerify`, `TestRememberDevice`, `TestDeviceGoneUnverifiedAllowed` |

## New (§4.2)

| Identifier | Interface | Checked |
|---|---|---|
| `New`, `Auth`, `Option` | refuses a short secret and §4.8's ranges (A9) | `TestNewRefusesBadConfig` |
| `WithClaims`, `WithRecorder`, `WithPolicy`, `WithReject`, `WithClock` | as §4.2 | the tests above; `TestWithReject` |
| `WithFirst` | the first proofs, the same for every login | `TestNewRefusesBadConfig`, `TestFirstProven`, `TestUnknownLoginCode` |
| `WithMethods` | modules (§4.9); refused before v0.2.0 (A19) | `TestNewRefusesBadConfig` |
| `WithClientAddr`, `WithClient` | the client behind proxies; outside a request | `TestLoadClient`; the throttle tests |

## Flows (§4.3)

| Identifier | Interface | Checked |
|---|---|---|
| `Purpose` and its five constants | as §4.3 | `TestEnrollPassword`, `TestStepUp` |
| `MethodPassword` … `MethodRecoveryCode` | the six names | `TestCodeAsSecondProof`, `TestEnrollTOTP`, `TestRecoveryCodesMade` |
| `Flow` (`Token`, `Purpose`, `Ready`, `Verified`, `Offers`, `Expires`) | as §4.3, with A5 for a step-up | `TestSignIn`, `TestStepUpOffersAndDisabled`, `TestFlowLifetime` |
| `Flow.Write`, `FlowToken` | the flow cookie, read back through `Load` | `TestFlowTokenThroughLoad`, `TestCookies` |
| `SignIn`, `StepUp`, `Recover`, `Accept`, `Enroll` | the five starters; only `SignIn` takes a carrier | `TestSignIn`, `TestStepUp`, `TestRecoverByLink`, `TestInviteAccept`, `TestEnrollPassword` |
| `StartOption`, `Device` | a stored device token | `TestRememberDevice`, `TestDeviceRefusals` |
| `Follow` | changes nothing a second call wouldn't; A11's rotation | `TestRecoverByLink`, `TestRecoverStarterCantFinish` |
| `Auth.Flow` | a flow's state | `TestRecoverByLink`, `TestReplacedTokenInOlderFlow` |
| `Challenge`, `Auth.Challenge` | `SentTo` masked, `Resend`, `TOTP` when enrolling; `Options` for modules | `TestMaskAndCodes`, `TestCodeResend`, `TestEnrollTOTP` |
| `TOTPSetup` | base32 secret and `otpauth://` URI | `TestEnrollTOTP`, `TestTOTPURIEscaped` |
| `Prove`, `Proof`, `Password`, `EmailCode`, `SMSCode`, `TOTP`, `RecoveryCode` | as §4.3 | `TestPasswords`, `TestCodeRefusals`, `TestTOTPReplay`, `TestRecoveryCodeOnce` |
| `Finish`, `FinishOption`, `NewPassword`, `Remember`, `RememberDevice` | as §4.3 | `TestSignIn`, `TestRecoverByLink`, `TestRememberedIdle`, `TestRememberDevice` |
| `Carrier`, `Cookie`, `Bearer` | the two carriers, kept apart | `TestCarriersApart`, `TestCookieOnlyNamesCookieSessions`, `TestAccessNamesBearerSessions` |
| `Result` (`Session`, `Access`, `Refresh`, `Device`, `RecoveryCodes`), `Result.Write` | as §4.3, A17 for recovery codes | `TestBearerSignIn`, `TestRecoveryCodesMade`, `TestCookies` |

## Sessions and requests (§4.4)

| Identifier | Interface | Checked |
|---|---|---|
| `SessionID`, `DeviceID`, `Session`, `Factor` | as §4.4 | `TestSessionsList`, `TestOneProofIsOneFactor` |
| `Load` | attaches the session and client; the cross-origin check (A8) | `TestCrossOrigin`, `TestNestedLoad`, `TestLoadClient` |
| `Require`, `Check`, `Requirement` | Verified unless every requirement names its level (A18) | `TestRequireLevels`, `TestCombinedLevels`, `TestRememberDevice` (`Check`) |
| `From` | the request's session | every request test |
| `Level`, `Verified`, `Unverified`, `Level.Check` | `Level` is a `Requirement` | `TestRequireLevels` |
| `Within` | a proof no older than d; a device doesn't count | `TestWithin`, `TestRememberDevice` |
| `Refresh`, `Reissue` | A14 | `TestRefresh`, `TestRefreshReplay`, `TestRefreshConcurrent`, `TestReissue` |
| `SignOut` | ends the carried session | `TestSignOut`, `TestSignOutKeepsCookieOnError` |
| `Revoke`, `RevokeUser` | only the named user's session | `TestRevokeOtherUser`, `TestRevokeUser`, `TestAcceptRevoke` |
| `Sessions` | live sessions, oldest first | `TestSessionsList`, `TestSessionsLeavesOutIdle` |
| `Devices`, `DeviceInfo`, `ForgetDevice` | `DeviceInfo` has an ID, a label and three times | `TestForgetDevices`, `TestSweepDevices` |

## Management (§4.5)

| Identifier | Interface | Checked |
|---|---|---|
| `CheckPassword`, `SetPassword` | A3's strength rules; setting ends sessions | `TestPasswords`, `TestAcceptPasswords`, `TestSetPasswordEndsSessions` |
| `Invite` | an invitation token | `TestInviteAccept`, `TestInviteNotSent` |
| `Factors`, `FactorInfo`, `RemoveFactor`, `ResetFactors` | A15 | `TestFactors`, `TestRecoveryCodesAndFactors`, `TestEnrollRecheckedInTransaction` |
| `DeleteUser` | everything auth holds for the user (A19) | `TestDeleteUser` |
| `Sweep` | removes what has expired | `TestSweep`, `TestSweepLinks`, `TestSweepDevices`, `TestSweepRefresh` |
| `Rekey` | re-seals under the current secret | `TestRekey`, `TestRekeyReportsLost`, `TestRecoveryCodesAcrossRotations` |

## Errors (§4.6)

| Identifier | Interface | Checked |
|---|---|---|
| The 18 errors of §4.6's table | each `errors.auth.<name>`, with its kind | `TestErrorTable` |
| `RetryAfter` | the longest wait in force | `TestRetryAfterLongest`, `TestThrottleSixth` |

## `auth/access` (§4.7)

| Identifier | Interface | Checked |
|---|---|---|
| `Permission`, `Perm`, `Perm.Key`, `Perm.T`, `Permissions` | declared once; key `permission.<key>` | `TestPermissionDeclared`, `TestCanLevels` |
| `GroupID`, `Root`, `Group` | root holds every declared permission | `TestRoot` |
| `New`, `Access` | its own bucket | `TestGroups` |
| `Can`, `Check` | a requirement naming its level (A18); `Check` for code | `TestCan`, `TestCanLevels`, `TestRequireStatuses` |
| `CreateGroup` … `Granted` | as §4.7 | `TestGroups`, `TestUnknownGroup`, `TestRemoveUser` |
| `Stale` | granted keys no longer declared | `TestStale` |

## Config (§4.8)

| Identifier | Interface | Checked |
|---|---|---|
| `Config` | 28 getters, exactly §4.8's names | `go doc` diffed against the table; `TestAuthtestConfig`; `examples/shop` `settings_test.go` |
| `authschema.Group` | the cfgx group `auth`, `GoName("Auth")`, each key's range (A9) | `authschema` `TestGroup` |

## For modules (§4.9)

| Identifier | Interface | Checked |
|---|---|---|
| `Method`, `MethodInput`, `Credential`, `MethodResult`, `Identity` | as §4.9 | compile only: no engine path drives them before v0.2.0 (A19) |

## `auth/authtest` (§4.10)

| Identifier | Interface | Checked |
|---|---|---|
| `New`, `Kit`, `Kit.AddUser`, `Kit.LastMessage`, `Kit.Events` | as §4.10 | the acceptance tests, which use only the kit |
| `Clock` (`Advance`, `Now`) | a fake clock | `TestAcceptSessionLifetimes` |
| `Config`, `Values` | the defaults with cheap hashing; panics outside `go test` | `TestAuthtestConfig` |

## Findings

1. **`DeleteUser` was missing.** §4.5 declares it and `access.RemoveUser`'s
   doc refers to it, but no milestone named it. Added, with A19 settling
   what the contract left open, and `TestDeleteUser`, which reads every
   bucket for the user's ID, session IDs and device ID afterwards, checks
   that another user keeps his password, device and sessions, that a
   recovery already followed can't set a password, and the events. Removing
   any of its ten parts, or widening it to another user's records, fails
   the test.
2. **`WithMethods` accepted modules the engine never drives.** A module's
   method named in `WithFirst` would have been offered and then refused
   with `ErrMethodUnavailable`. `New` now refuses modules until v0.2.0
   (A19). The types of §4.9 stay, so `auth/passkey` can be built against
   them.
3. **Exported beyond §4's code blocks, all named in its prose:**
   `DeviceInfo`, `FactorInfo`, `Option`, `StartOption`, `FinishOption`,
   `Carrier`, `Level.Check`, `authtest.Values`, `Clock.Advance` and
   `Clock.Now`. None is new API.
4. **Named results differ:** §4 writes `Invite`'s and `Reissue`'s results
   as `(token string, err error)` and `(access string, err error)`; the code
   leaves them unnamed. The same API.
5. **`authschema` requires the core through a `replace`.** The release
   (M6.4) tags the core first, then `authschema/v0.1.0` with the replace
   dropped and the require pinned (ADR 0004).

The API is §4's. Findings 1 and 2 changed code; the rest need nothing.

# API review for v0.2.0 (M7.3)

Every identifier added since v0.1.0, as `go doc -all` lists them on
2026-11-17, against what epistemer locked on 2026-11-17 (interface §4.3,
§4.9, §4.11, amendment A21). The method was the same: a mechanical diff
of the declarations, then each by hand. Nothing else exported changed.

## `auth` (§4.2, §4.3, §4.9)

| Identifier | Interface | Checked |
|---|---|---|
| `WithMethods` | accepted; refuses a nil method, two of a name, a built-in name, a name outside `[a-z0-9_]{1,32}` (A19 withdrawn) | `TestNewMethods` |
| `MethodPasskey` | D27; a passkey is an enrolled factor (§5.13.12) | `TestModuleEnroll`; `passkey` `TestPasskey` |
| `SignInWithout` | D32; offers `WithFirst`'s module methods, else `ErrMethodUnavailable` | `TestSignInWithout`, `TestSignInWithoutThrottle`, `TestSignInWithoutDeviceCounters` |
| `FactorLabel` | D33; cut at 64, control characters dropped; authenticator apps too | `TestModuleEnroll`, `TestFactorLabelTOTP`, `TestModuleOwnLabelCleaned` |
| `Refuse` | D34; wraps `ErrBadCredentials`, a fixed text, the reason only in the event | `TestRefuse` |
| `MethodInput.Now` | D36; the engine's clock | `TestSignInWithout`; `passkey` `TestExpiresByTheEnginesClock` |

## `authschema` (§4.11, D29)

| Identifier | Interface | Checked |
|---|---|---|
| `Group(members ...dsl.Member)` | variadic: every existing call compiles | the test app; `examples/shop` |
| `Passkey()` | the group `passkey`: `domain` (required) and `origins` | test app `TestPasskeyKeys`, `TestRanges`; `examples/shop` `settings_test.go` (`passkey.Config`) |

## `auth/passkey` (§4.11, D28, D30, D31)

| Identifier | Interface | Checked |
|---|---|---|
| `Config` | `AuthIssuer`, `AuthPasskeyDomain`, `AuthPasskeyOrigins` | `examples/shop` `settings_test.go` |
| `New` | refuses each bad config of §4.11; returns an `auth.Method` | `TestNew`, `TestNewStricter`, `TestOrigins` |
| `Response` | the JSON of `PublicKeyCredential.toJSON()`; prints no bytes | `TestNoLibraryText`, every sign-in test |
| `Challenge.Options` | a `json.RawMessage`, unwrapped | `TestCreationOptions`, `TestRequestOptions` |

## `auth/passkey/passkeytest` (§4.11, D35)

| Identifier | Interface | Checked |
|---|---|---|
| `Authenticator`, `New`, `Create`, `Get` | one ES256 passkey; a second `Create` fails the test | `passkey` `TestPasskey`, `TestTwentyPasskeys`; `examples/shop` `TestPasskey` |

## Findings

None. The declarations are §4.11's and §4.3's, word for word; the
passkey module's types from go-webauthn appear nowhere in its API.

# API review for v0.3.0 (M8.3)

Every identifier added since v0.2.0, as `go doc -all` lists them on
2026-11-17, against what epistemer locked on 2026-11-17 (interface §4.3,
§4.5, §4.9, §4.12, amendment A25). Nothing else exported changed.

## `auth`

| Identifier | Interface | Checked |
|---|---|---|
| `Flow.Unlinked`, `Link` | D42; only in a `SignInWithout` flow; the user new to auth (§5.14.7) | `TestLink`, `TestLinkNotNew`, `TestLinkDuplicate`, `TestLinkRaces`; `oidc` `TestSignInAndLink`; `examples/shop` `TestOIDC` |
| `Identities`, `IdentityInfo`, `Unlink` | D44; no factor; `Unlink` refuses the last way in | `TestIdentitiesAndUnlink`, `TestUnlinkEdges` |
| `AddressOnly` | D43; replaces the core's list | `TestAddressOnly`; `passkey`, `oidc` `TestAddressOnly` |
| `MethodResult.Address` | D45; one mailbox, one factor (§5.7.2) | `TestOneMailboxOneFactor`, `TestLinkEdges` |

## `authschema`

| Identifier | Interface | Checked |
|---|---|---|
| `OIDC()` | the group `oidc`: provider, issuer, client_id, client_secret, redirect_url, scopes, two_factors, with pinned getter names | the test app (`oidc.Config`'s getters), `TestRanges`; `examples/shop` `settings_test.go` |

## `auth/oidc`

| Identifier | Interface | Checked |
|---|---|---|
| `Config` | D39's seven getters | `examples/shop` `settings_test.go` |
| `New` | refuses each bad config of §4.12; no network call; method `oidc_<provider>` | `TestNew` |
| `Callback` | D41; the provider names the method; prints no secret | `TestRefusals`, `TestOnceAndExpiry`, `TestNew` |
| `Challenge.Options` | D40; the authorization URL, a `string` | `TestSignInAndLink` |

## Findings

None. The declarations are §4.3's, §4.5's, §4.9's and §4.12's, word for
word; no go-oidc, go-jose or x/oauth2 type appears in the module's API.
