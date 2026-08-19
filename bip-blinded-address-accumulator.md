<pre>
  BIP: XXX
  Layer: Applications
  Title: Blinded Address Accumulator
  Author: &lt;to be assigned&gt;
  Comments-Summary: No comments yet.
  Comments-URI: https://github.com/bitcoin/bips/wiki/Comments:BIP-XXX
  Status: Draft
  Type: Standards Track
  Created: 2026-08-19
  License: BSD-2-Clause
</pre>

## Abstract

This proposal defines an accumulator over a payee's receiving addresses that
grants a payer verification without enumeration. A payee commits, in a Merkle
tree whose leaves are blinded commitments, to a set of addresses they control;
a signing device builds the tree and signs the root, which the payer pins once
over an out-of-band channel. Thereafter every address the payee reveals comes
with a Merkle proof, and the payer verifies membership against the pinned root.
The accumulator trades verification for no surveillance power: revealing an
address reveals nothing about addresses not revealed, in contrast with sharing
an xpub, which permanently exposes every address the payee will ever use.

## Motivation

Address substitution is the dominant practical threat to bitcoin payment
security. A compromised web server, an intercepted email, clipboard malware, or
a tampered QR frame substitutes an attacker's address for the payee's, and the
transaction is irreversibly settled before anyone notices. The defenses in
common use reduce to two: the payer inspects an address string by eye, which is
fragile and forces recipients into a choice between reuse and verification
overhead; or the payee shares an xpub, which eliminates the substitution
problem but grants the payer permanent, undetectable surveillance over every
address the payee will ever derive.

What is wanted is certificate pinning for payment addresses: a one-time
commitment that scopes verification to exactly the addresses revealed and to
nothing more. This proposal provides it.

The strongest practical argument for this design is what happens when both
parties run signing devices. The payer's device verifies proofs itself and
displays a **contact name** instead of an address string. Recipient
verification moves behind the trusted display: the human confirms they are
paying the contact they intended, and the address binding is enforced by the
device. This is the property that address-string comparison reaches for and
cannot attain, because an address is not a name and a human is not a hash
function. Once the payer's device authenticates a contact, the address need
never be shown to the human at all.

The reason this is not simply "share an xpub" is the surveillance asymmetry.
An xpub is a permanent enumeration capability. The accumulator is a
verification capability scoped per revealed address. That trade is the
contribution.

Throughout this document the roles are fixed: the **payee** receives bitcoin,
the **payer** sends it. These terms are held consistently and the more common
"sender"/"receiver" pair is avoided because it is ambiguous about who is
receiving what.

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHOULD", "SHOULD NOT", and
"MAY" in this document are to be interpreted as described in RFC 2119.

### Tagged hashing

All hashes in this specification are BIP340-style tagged hashes:

```
tagged_hash(tag, data) = sha256(sha256(tag) || sha256(tag) || data)
```

The following tags are used. Throughout this document, `bipXXX` is a literal
placeholder for the assigned BIP number; implementations MUST substitute the
final assigned number in every tag string.

| Purpose | Tag |
|---|---|
| Leaf | `bipXXX/leaf/v1` |
| Padding leaf | `bipXXX/pad/v1` |
| Internal node | `bipXXX/branch/v1` |
| Root commitment | `bipXXX/root/v1` |
| Proof of Recipient | `bipXXX/por/v1` |

### Nonce derivation

All blinding material derives from the wallet descriptor. There is no separate
seed and no separate backup.

```
policy_id  = sha256(canonical_wallet_policy)
key_digest = sha256(concat_all(sort(dedup(serialized_xpubs))))
nonce_key  = hmac_sha512("bipXXX nonce", concat(policy_id, key_digest))[0:32]

nonce(branch, index) = hmac_sha512(nonce_key,
                                   concat(u8(branch), be32(index)))[0:32]
```

`canonical_wallet_policy` is the wallet policy serialization defined by
BIP388. Implementations MUST NOT invent an alternate serialization.

`branch` is 0 for the receive branch and 1 for the change branch. A third
domain, `branch = 2`, is reserved for padding nonces and is disjoint from both.
`u8(branch)` is `branch` as a single unsigned 8-bit integer. `be32(index)` is
`index` as a 32-bit big-endian unsigned integer.

`nonce(branch, index)` MUST be computed directly from `nonce_key` as a single
HMAC. Implementations MUST NOT derive nonces by chaining one index's nonce to
the next. Random access is required: serving a proof for a high index MUST cost
one HMAC, not many.

### Leaf construction

```
leaf(branch, index) = tagged_hash("bipXXX/leaf/v1",
                                  concat(nonce(branch, index),
                                         script_pubkey(branch, index)))

pad(position) = tagged_hash("bipXXX/pad/v1", nonce(2, position))
```

`script_pubkey(branch, index)` is the scriptPubKey of the address at the given
derivation branch and index. The commitment is to the scriptPubKey, not to any
address encoding.

The `branch = 2` argument to `nonce` in `pad` places padding nonces in a domain
disjoint from the receive and change branches.

### Tree construction

The tree has exactly three levels. There is one size parameter, `n`, which
MUST be a power of two. Total capacity is `n * n * n`.

```
build(n):
    level1 = []
    for each group of n consecutive indices:
        hashes = [leaf(branch, i) for i in group]
        sort_bytewise(hashes)
        level1.append(collapse(hashes))

    level2 = []
    for each group of n entries in level1:
        sort_bytewise(group)
        level2.append(collapse(group))

    sort_bytewise(level2)
    return collapse(level2)

collapse(nodes):
    while length(nodes) > 1:
        if length(nodes) is odd:
            nodes.append(pad(next_pad_position))
        nodes = [branch_hash(nodes[2k], nodes[2k+1]) for each pair]
    return nodes[0]

branch_hash(left, right) = tagged_hash("bipXXX/branch/v1",
                                       concat(left, right))
```

`sort_bytewise` sorts its input as a list of byte strings in unsigned
lexicographic order.

The following three requirements each apply to every implementation:

1. `sort_bytewise` is applied at all three levels: leaf hashes within a
   first-level group, first-level roots within a second-level group, and
   second-level roots at the top. Implementations MUST NOT omit any of these
   sorts.

2. Whenever the input to `collapse` has odd length, a padding leaf is appended.
   Implementations MUST NOT instead duplicate the final node.

3. Inside `branch_hash`, the two children are combined in the order given.
   Implementations MUST NOT sort the two children before hashing.

Unused capacity at the top of the tree is filled with padding leaves so that
the tree is always exactly full. `next_pad_position` is a counter of padding
leaves consumed, beginning at 0 and incremented monotonically across all
invocations of `collapse` within a single `build`.

### Root commitment and signature

```
commitment = tagged_hash("bipXXX/root/v1", concat(u8(height), root))
```

`height` is the total tree height, equal to `3 * log2(n)`, where the
multiplication is exact because `n` is a power of two. `height` MUST be a
multiple of three; verifiers MUST reject a `height` that is not. `n` is derived
as `2 ^ (height / 3)` and is not transmitted.

The commitment is signed by a long-lived identity key at a fixed derivation
path. The path is normative; the specific path is an open item
(see [[#open-items]]). Until finalized, implementations MUST treat the path as
unspecified and MUST NOT ship interoperable code relying on a guessed value.

### Proof format and verification

A proof consists of a nonce, a tree position, and one sibling per level.

```
proof = { nonce: 32 bytes,
          position: u32,
          siblings: [32 bytes; height] }

verify(address, proof, pinned_root):
    node = tagged_hash("bipXXX/leaf/v1",
                       concat(proof.nonce, script_pubkey_of(address)))
    for level in 0 .. height:
        sibling = proof.siblings[level]
        if bit(proof.position, level) == 0:
            node = branch_hash(node, sibling)
        else:
            node = branch_hash(sibling, node)
    return node == pinned_root
```

`position` is a 32-bit unsigned integer. `bit(position, level)` is bit `level`
of `position`, with bit 0 being the least significant.

`script_pubkey_of(address)` decodes the address to its scriptPubKey. When the
address is already available as a scriptPubKey, decoding is not required.

Verification holds one 32-byte accumulator and consumes each sibling as it
arrives. Working memory is therefore constant regardless of tree size: 32 bytes
for the running node plus one 32-byte sibling at a time. This is what makes the
construction viable on constrained hardware such as a secure element.

Proof sizes by tree height (nonce 32 + position 4 + siblings 32 each):

| Height | Capacity | Proof size (bytes) |
|---|---|---|
| 9 | 512 | 324 |
| 12 | 4,096 | 420 |
| 18 | 262,144 | 612 |
| 21 | 2,097,152 | 708 |

### Payer-side device flow

Three operations are defined. All three are OPTIONAL for a payer that verifies
proofs in software on a general-purpose host. All three are REQUIRED for a
payer implementation running on a signing device.

#### Contact registration

The device does not store contacts in persistent memory. It authenticates a
registration record and returns it to the host, which stores it and presents it
back when needed.

```
record = { contact_name, identity_pubkey, root, height }
tag    = hmac_sha256(device_secret, serialize(record))
```

At registration the device MUST display the contact name and a root
fingerprint for user confirmation. The user MUST confirm against a value
received out of band.

Because the record stores `identity_pubkey` and not only `root`, a later root
signed by the same identity key MAY be accepted without user interaction: the
device verifies the signature against the stored pubkey and re-issues the
record.

#### Proof of Recipient issuance

Verification is a statement about an address and a tree and involves no
transaction. A device MAY verify a proof at address-receipt time and issue a
token binding the address to the contact:

```
por = hmac_sha256(device_secret,
                  concat("bipXXX/por/v1", script_pubkey, contact_name))
```

#### Proof of Recipient redemption

At signing time, for each transaction output:

```
expected = hmac_sha256(device_secret,
                       concat("bipXXX/por/v1",
                              tx.outputs[j].script_pubkey,
                              contact_name))
accept if expected == supplied_por
```

The scriptPubKey MUST be read from the transaction output being signed. It
MUST NOT be read from data accompanying the token. The attack prevented by
this requirement is: a host presents a valid Proof of Recipient for an address
the contact genuinely controls while the transaction pays a different
scriptPubKey. Binding the token to the output's own scriptPubKey makes this
attack fail.

A device MAY instead verify a full proof during signing, for the case where the
device was unavailable at address-receipt time.

### PSBT field

For the verify-during-signing fallback, the following per-output proprietary
PSBT field is defined:

```
key:   PSBT_OUT_PROPRIETARY | "bipXXX" | 0x01
value: nonce (32) || position (varint) || siblings (32 each)
```

The field is scoped to a single output, so the binding between proof and
output scriptPubKey is structural: the proof applies to the output in whose map
it appears.

`contact_root` is deliberately not carried in the PSBT. The root is taken from
the registration record authenticated by the device. If a host could supply
both proof and root, it could verify a proof against a root of its own
choosing.

The default flow carries only a Proof of Recipient, passed as a signing
parameter. A Merkle proof therefore need not appear in a PSBT at all in normal
operation.

## Rationale

**Blinded leaves rather than raw addresses.** An unblinded tree lets anyone
holding it test a candidate address for membership by hashing it and walking
the structure. That is exactly the surveillance property the design exists to
remove. Blinding each leaf with a secret-keyed nonce makes the leaf hiding as
well as binding: an observer with the tree but without the nonce key cannot
test membership, and the payer — the party the blinding protects against — does
not hold the nonce key.

**Nonces derived from the descriptor rather than an independent seed.** In a
multisig setting, a nonce key derived from one cosigner's seed leaves the
other cosigners unable to rebuild the tree, and the failure surfaces only at
recovery time, when the missing cosigner is least likely to be reachable.
Deriving from the aggregated descriptor means any cosigner holding the
descriptor can rebuild the tree from scratch. This costs no privacy: anyone
holding the xpubs can already enumerate addresses directly, and the payer —
the party blinding protects against — holds neither the descriptor nor the
xpubs.

**HMAC rather than BIP32 child derivation.** The nonce is a blinding value,
not a curve point, so scalar multiplication buys nothing and costs
non-negligible time on a secure element. HMAC also makes the security argument
simpler: under standard PRF assumptions, revealing one nonce leaks nothing
about any other, which is the property the proof format relies on.

**Commitment to the scriptPubKey rather than the address string.** Address
encodings vary — bech32 versus bech32m, casing on chain, future encodings.
The scriptPubKey is the bytes that actually appear in the transaction, and is
what the verifier can extract unambiguously without an encoding decision.

**Placement by sorted leaf hash rather than by derivation index.** If leaves
sat at their derivation index, the tree position would reveal the index, which
leaks how many addresses the payee has used and in what order. The leaf hash
is already a secret-keyed pseudorandom value because it contains the nonce, so
sorting by it yields a keyed permutation at no extra cost.

**Sorting rather than an explicit keyed permutation.** A Feistel construction
would give the same decorrelation in a single device-autonomous pass. It was
rejected because it must be specified exactly — round count, bit width,
endianness, round function — and a wrong reimplementation fails silently by
producing a different root with no detectable error. Bytewise comparison of
32-byte hashes is unambiguous in every language. When a parameter is fixed in
the specification rather than negotiated, the deciding criterion is which
primitive is hardest to get subtly wrong.

**Ordered children rather than BIP341-style sorted siblings.** BIP341 sorts
sibling pairs because a TapTree proof needs only membership, so direction bits
are redundant and can be dropped. Here the position is transmitted regardless.
Sorting the two children would therefore save nothing and would make a single
proof verify at multiple positions, reducing the position to an unauthenticated
hint rather than a binding selector.

**Padding rather than duplicating the final node.** Duplicating the final node
to round out an odd count is CVE-2012-2459 in the Merkle-tree setting: it
makes distinct trees share a root. Padding with a domain-separated leaf also
fills the tree completely, so the number of real addresses cannot be inferred
from the tree's structure.

**Version in the tag strings rather than a header field.** A future revision
of this proposal uses `/v2` tags. Because the tag is inside the hash,
signatures and proofs under the two versions are non-interchangeable by
construction. This costs zero bytes and removes a version field that could
disagree with the data it purports to describe.

**No count of real addresses in the signed data.** Padding exists to hide the
number of real addresses. Signing that number would hand it to the payer,
cancelling the feature. An earlier revision of this design made this mistake;
it is called out here so reviewers do not reintroduce it.

**Only `height` in the header.** Everything other than `height` is a pure
function of the descriptor and is therefore already committed transitively by
the root. `height` is the exception because device capability varies: a fixed
constant would either exclude constrained hardware or force every
implementation to the weakest. Transmitting `height` lets each payee pick the
largest tree their hardware can build.

**Fixed three-level structure.** Peak device memory during build is `3 * n`
hashes: 48 hashes at 4,096 addresses, 192 at 262,144. A flat build with a
single bucket width costs the square root of the total in memory. A streaming
build costs less still but requires the host to feed indices in sorted order,
which the three-level structure avoids: the device enumerates consecutive
indices, sorts within each bucket, and never holds more than one bucket. The
cost is granularity: only heights that are multiples of three are
representable.

**Long-lived identity key.** Without a stable identity key, tree exhaustion
would force a fresh out-of-band ceremony with every payer at a moment the
payee does not choose — typically the moment a new payment is already pending.
Signing each root under a stable identity key means a larger tree can be
accepted automatically by any payer who stored the pubkey, converting a
recurring coordination cost into a one-time one.

**Proof of Recipient.** Verification is transaction-independent, so it can
happen once per address rather than once per signing session. Over animated QR
transport at roughly 200 bytes per frame, a full Merkle proof adds several
frames per output; a 32-byte token is a fraction of one frame. The token also
survives RBF fee bumps and repeat payments to the same recipient, neither of
which a per-signing proof would need to be re-sent for.

## Backwards Compatibility

This proposal introduces no changes to consensus rules, transaction structure,
or on-chain data. Proofs travel out of band or in PSBT proprietary fields that
are stripped at finalization. Software that does not implement this proposal
ignores the unknown proprietary PSBT field and is otherwise unaffected. There
is no upgrade path required for existing wallets to continue functioning.

## Reference Implementation

A reference implementation is TBD. It MUST be the source of the test vectors
below; vectors MUST NOT be authored by hand.

## Test Vectors

**OPEN ITEM — must be generated from a working reference implementation.**
Hand-authored vectors will not be accepted. The vector set MUST cover, at
minimum:

- A small tree (for example height 9, capacity 512) with every intermediate
  value printed: per-leaf nonces, per-leaf hashes, per-bucket sorted order,
  every branch hash, every padding leaf, the root, and the signed commitment.
- A tree that requires padding at more than one level, exercising both the
  odd-bucket and odd-top-level cases.
- A multisig descriptor exercising xpub serialization, sort, and deduplication
  in `key_digest`.
- At least one full proof with its complete verification trace: the running
  node value before and after each level, the sibling consumed at each level,
  and the bit of `position` that selects the ordering at each level.
- At least one negative vector: a proof that fails because the scriptPubKey in
  the address does not match the nonce, and one that fails because a sibling
  is altered.

## Open Items

The following items are unresolved. Implementations MUST NOT fabricate values
for them; interoperable deployments require they be settled first.

- **BIP number.** Every tag string contains `bipXXX` as a placeholder. The
  assigned BIP number replaces it throughout, including inside the
  `hmac_sha512("bipXXX nonce", ...)` salt and the `"bipXXX/por/v1"` literal.

- **Identity key derivation path.** A long-lived identity key signs the root
  commitment at a fixed derivation path distinct from any address key.
  Candidate path (flagged for review, not normative):
  `m/<PURPOSE>'/0'/0'`, where `<PURPOSE>` is the hardened purpose number
  equal to the assigned BIP number. This path is proposed because it is
  disjoint from existing registered purposes and is recoverable from the BIP
  number alone, but it has not been reviewed against the full registered
  purpose space and MUST NOT be relied on until settled.

- **Change branch.** Only the receive branch is required for the payer-facing
  flow, because payers never verify change addresses. Omitting the change
  branch produces smaller trees and a simpler build. Including it costs one
  byte in the nonce input (`u8(branch)` already accommodates it) and permits a
  future self-transfer verification flow in which a wallet proves its own
  change outputs to itself across devices. **Recommendation: include the change
  branch.** Flagged for review.

- **Signature scheme.** BIP340 Schnorr is the obvious default for the root
  commitment signature, reusing existing secure-element support. The exact
  message format — whether the signed message is the raw `commitment` bytes,
  a tagged wrapper, or includes a domain prefix — is an open item. The scheme
  and message format MUST be fixed before this proposal is finalized.

- **Recommended default for `n`.** Consumption runs ahead of payment count
  because wallets skip indices on gap-limit exhaustion, address reuse, and
  manual derivation. The default should be generous. **Suggested default:
  `n = 16` (height 12, capacity 4,096)**, on the grounds that 4,096 addresses
  comfortably exceeds the consumption of a typical long-lived contact while
  keeping peak build memory at 48 hashes and proof size at 420 bytes. Flagged
  for review; constrained-hardware deployments MAY choose `n = 8` (height 9,
  capacity 512) and high-volume payees MAY choose `n = 32` or larger.

- **Test vectors.** As above, MUST be generated from the reference
  implementation.

## Acknowledgements

TBD.

## Copyright

This document is licensed under the BSD 2-clause license.
