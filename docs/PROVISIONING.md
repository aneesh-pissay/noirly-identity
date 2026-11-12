# Provisioning and the identity lifecycle

How a space (organization) keeps its people in step with its directory: SCIM 2.0 from Entra ID or Okta, just-in-time accounts at single sign-on, offboarding and reactivation, bulk invitations and CSV import, and reconciliation. Single sign-on itself is in [SSO.md](SSO.md).

## Whose identities a space manages

A space manages the identities at its **verified domains** (Business domains in the space's settings). For those, it may create accounts, adopt existing ones, update their names, and lock them when they leave. For anyone else in the space (a contractor with their own address), it manages only their **membership**: deactivating them takes them out of the space, not off Noirly.

## SCIM 2.0

Tenant URL: `https://<identity>/api/scim/v2`. Authentication: a bearer token from the space's settings (**Directory → Provisioning → Create token**; shown once; owners, or admins with the domains area). Up to five tokens per space, each revocable. Owners are emailed when a token is made or revoked.

Supported: `Users` and `Groups` (create, read, list with `attr eq "value"` filters, replace, patch, delete), `ServiceProviderConfig`, `ResourceTypes`, `Schemas`. Not supported: bulk, sorting, ETags, password changes.

### Users

| SCIM | Noirly |
| --- | --- |
| `userName` | the email address; must be at a verified domain |
| `externalId` | the directory's id for the person, kept on their membership |
| `name.givenName`, `name.familyName`, `displayName` | the profile (owned identities only) |
| `active` | `false` deactivates (below); `true` reactivates |

Creating a user whose address already has an account **adopts** that account (it joins the space; no duplicate is made), also when the address is a confirmed additional address of an account. It's a conflict (`409`) only when the person is already provisioned under another `externalId`. New accounts are created confirmed (the space owns the domain); their owner signs in through single sign-on, or sets a password with "Forgot password". They're emailed that the organization made the account and how to sign in; an adopted account's owner is emailed that the organization now manages it.

`DELETE` deactivates and then removes the person from the space for good; an owned identity stays locked.

### Groups

Groups are the space's teams: creating a group creates a team, members follow the group. Only members of the space can be in a team; other ids are ignored.

**Groups to roles:** under *Directory groups whose members are admins*, name groups (by display name). Directory-provisioned members of those groups are the space's admins; other provisioned members are members. People added by hand keep their role, and owners are never changed.

### Microsoft Entra ID

1. **Enterprise applications** → your Noirly application (or a new non-gallery one) → **Provisioning** → **Automatic**.
2. Tenant URL: `https://<identity>/api/scim/v2`. Secret token: the Noirly token. **Test connection**.
3. Mappings: the defaults work (`userPrincipalName` or `mail` → `userName`, `objectId` → `externalId`, `Switch([IsSoftDeleted]…)` → `active`). Make sure `userName` is the address at your verified domain.
4. Assign users and groups, then turn provisioning **On**.

Entra sends `PATCH` with capitalized ops and string booleans (`"op": "Replace", "value": "False"`), and removes group members with `members[value eq "…"]`; both are handled.

### Okta

1. Your Noirly app integration → **General** → *Provisioning: SCIM*. Then **Provisioning → Integration**: SCIM connector base URL `https://<identity>/api/scim/v2`, unique identifier field `userName`, actions *Push New Users, Push Profile Updates, Push Groups*, authentication *HTTP Header* with the Noirly token.
2. **To App**: enable *Create Users, Update User Attributes, Deactivate Users*.
3. Assign people; use **Push Groups** for the groups that should become teams.

## Just-in-time accounts

With single sign-on's *create accounts on first sign-in* (the default), someone signing in through the space's IdP for the first time gets an account and joins the space as a member, with roles and teams from their IdP groups (see SSO.md). Without SCIM, that's the whole of provisioning.

## Offboarding

Deactivating someone (SCIM `active: false`, the space's bulk actions, or **Directory → Deactivate**):

- removes their membership and their teams at once, and revokes every token issued for the space;
- for an **owned identity**: locks the account (no sign-in of any kind), ends every session and revokes every token; apps that had sessions get back-channel logout, and apps subscribed to lifecycle webhooks get `user.deactivated`;
- sends `membership.changed` (`change: "deactivated"`) to subscribed apps;
- keeps what they had (role, admin areas, attributes, teams, directory id) for reactivation;
- emails the person: "turned off" for an owned identity, "no longer have access" otherwise. Reactivation emails them too.

Owners can't be deactivated (hand over ownership first). The person can't lift an organization's lock themselves (not even by freezing and unfreezing their account); an Identity admin can.

## Reactivation

`active: true` from the directory, **Reactivate** in the space's Directory section, or the bulk action: the membership comes back with its role, admin areas, attributes, teams and directory id, and an account the space locked is unlocked (`user.reactivated`, `membership.changed`).

## Bulk invitation, CSV import and bulk management

In the space's **Directory** section (admins with the members area), or `POST /api/spaces/<id>/directory`:

- `{ "action": "invite", "emails": [...], "role": "member" }`: up to 500 addresses.
- `{ "action": "import_csv", "csv": "..." }`: columns `email`, optional `role` (member, admin, owner) and `teams` (team names separated by `;`, joined on accepting).
- `{ "action": "manage", "userIds": [...], "change": { "action": "remove" | "role" | "deactivate" | "reactivate" | "add_to_team" | "remove_from_team", ... } }`.

Each row is handled on its own, with the same checks as one at a time (only owners invite owners, the last owner stays, …), and the answer lists what happened to each.

## Reconciliation

`GET /api/spaces/<id>/directory` (and the Directory section) reports:

- **possible duplicates** at the space's domains: the same address but for a `+tag`, or one account's confirmed additional address being another's sign-in address. Merge them with the account merge flow, or deactivate the stray one;
- **unmanaged** members at the space's domains with no directory id (the directory won't deactivate them when they leave). Link one by hand with `{ "action": "link", "userId": "...", "externalId": "..." }`, or let SCIM adopt them by creating them;
- **outside** members, whose address isn't at the space's domains.

## Lifecycle webhooks

See *Lifecycle webhooks* in [INTEGRATION.md](INTEGRATION.md).
