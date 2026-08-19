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

This proposal defines an accumulator over a recipient's receiving addresses that
grants a sender verification without enumeration. A recipient commits, in a Merkle
tree whose leaves are blinded commitments, to a set of addresses they control;
a signing device builds the tree and signs the root, which the sender pins once
over an out-of-band channel. Thereafter every address the payee reveals comes
with a Merkle proof, and the sender verifies membership against the pinned root.
The accumulator trades verification for no surveillance power: revealing an
address reveals nothing about addresses not revealed, in contrast with sharing
an xpub, which permanently exposes every address the recipient will ever use.

## Motivation

Address substitution is the dominant practical threat to bitcoin payment
security. A compromised web server, an intercepted email, clipboard malware, or
a tampered QR frame substitutes an attacker's address for the recipient's, and the
transaction is irreversibly settled before anyone notices. The defenses in
common use reduce to two: the sender inspects an address string by eye, which is
fragile and forces recipients into a choice between reuse and verification
overhead; or the recipient shares an xpub, which eliminates the substitution
problem but grants the sender permanent, undetectable surveillance over every
address the recipient will ever derive.

What is wanted is certificate pinning for payment addresses: a one-time
commitment that scopes verification to exactly the addresses revealed and to
nothing more. This proposal provides it.

The strongest practical argument for this design is what happens when both
parties run signing devices. The sender's device verifies proofs itself and
displays a **contact name** instead of an address string. Recipient
verification moves behind the trusted display: the human confirms they are
paying the contact they intended, and the address binding is enforced by the
device. This is the property that address-string comparison reaches for and
cannot attain, because an address is not a name and a human is not a hash
function. Once the sender's device authenticates a contact, the address need
never be shown to the human at all.

The reason this is not simply "share an xpub" is the surveillance asymmetry.
An xpub is a permanent enumeration capability. The accumulator is a
verification capability scoped per revealed address. That trade is the
contribution.

Throughout this document the roles are fixed: the **recipient** receives
bitcoin and the **sender** sends it.

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHOULD", "SHOULD NOT", and
"MAY" in this document are to be interpreted as described in RFC 2119.

### Tagged hashing

All hashes in this specification are BIP340-style tagged hashes:

```
tagged_hash(tag, data) = sha256(sha256(tag) || sha256(tag) || data)
```

The following tags are used. Throughout this document, `BIPXXX` is a literal
placeholder for the assigned BIP number; implementations MUST substitute the
final assigned number in every tag string.

| Purpose | Tag |
|---|---|
| Leaf | `BIPXXX_LEAF` |
| Internal node | `BIPXXX_BRANCH` |
| Root | `BIPXXX_ROOT` |
| Nonce derivation | `BIPXXX_NONCE` |
| Shuffle key and stream | `BIPXXX_SHUFFLE` |
| Proof of Recipient | `BIPXXX_POR` |

### Nonce derivation

Leaf blinding material derives from a rolling chaincode and the descriptor keys
digest.

```
policy_id  = sha256(canonical_wallet_policy)
key_digest = sha256(concat_all(sort(dedup(serialized_xpubs))))

next_chaincode, nonce = split32(hmac_sha512(chaincode,
                                            concat("BIPXXX_NONCE",
                                                   key_digest,
                                                   be32(keychain),
                                                   be32(index))))
```

`canonical_wallet_policy` is the wallet policy serialization defined by
BIP388. Implementations MUST NOT invent an alternate serialization.

`keychain` identifies the descriptor keychain. `be32(keychain)` and
`be32(index)` are 32-bit big-endian unsigned integers.

Nonce derivation is sequential inside a tree. Each leaf consumes the current
chaincode and produces the next chaincode and that leaf's nonce by splitting the
64-byte HMAC output into two 32-byte halves.

### Leaf construction

```
leaf(script_pubkey, nonce) = tagged_hash("BIPXXX_LEAF",
                                         concat(script_pubkey, nonce))
```

`script_pubkey(index)` is the scriptPubKey of the address at the given
derivation index. The commitment is to the scriptPubKey, not to any address
encoding.

### Tree construction

Each tree contains exactly 256 leaves. Each shuffled entry is a one-byte offset
inside that tree. The absolute derivation index is the tree start plus that
offset.

```
build_tree(tree_start):
    assert tree_start % 256 == 0

    leaves = []
    nonces = []
    for offset in 0 .. 256:
        index = tree_start + offset
        chaincode, nonce = leaf_nonce(chaincode, key_digest, keychain, index)
        nonces[offset] = nonce
        leaves[offset] = leaf(script_pubkey(index), nonce)

    nodes = []
    for each offset in shuffle_order(shuffle_key(keys_digest)):
        nodes.append(leaves[offset])

    return root_hash(collapse(nodes))

collapse(nodes):
    while length(nodes) > 1:
        nodes = [branch_hash(nodes[2k], nodes[2k+1]) for each pair]
    return nodes[0]

branch_hash(left, right) = tagged_hash("BIPXXX_BRANCH",
                                       concat(left, right))

root_hash(root) = tagged_hash("BIPXXX_ROOT", root)
```

`shuffle_key(keys_digest)` is the tagged hash of `keys_digest` using the
`BIPXXX_SHUFFLE` tag. `shuffle_order(key)` returns the shuffled list of 256 byte
offsets.

The following three requirements each apply to every implementation:

1. The shuffle order is derived from the descriptor keys digest. Implementations
   MUST NOT use tree position as the derivation index.

2. A tree has exactly 256 leaves. Implementations MUST NOT use a different
   tree size.

3. Inside `branch_hash`, the two children are combined in the order given.
   Implementations MUST NOT sort the two children before hashing.

### Root signature

The root returned by tree construction is already domain-separated with
`BIPXXX_ROOT`.

The commitment is signed by a long-lived identity key at a fixed derivation
path. The path is normative; the specific path is an open item
(see [[#open-items]]). Until finalized, implementations MUST treat the path as
unspecified and MUST NOT ship interoperable code relying on a guessed value.

### Proof format and verification

A proof consists of a nonce, a tree position, and one sibling per level.

```
proof = { nonce: 32 bytes,
          position: u32,
          siblings: [32 bytes; 8] }

verify(address, proof, pinned_root):
    node = tagged_hash("BIPXXX_LEAF",
                       concat(script_pubkey_of(address), proof.nonce))
    for level in 0 .. 8:
        sibling = proof.siblings[level]
        if bit(proof.position, level) == 0:
            node = branch_hash(node, sibling)
        else:
            node = branch_hash(sibling, node)
    return root_hash(node) == pinned_root
```

`position` is a 32-bit unsigned integer. `bit(position, level)` is bit `level`
of `position`, with bit 0 being the least significant.

`script_pubkey_of(address)` decodes the address to its scriptPubKey. When the
address is already available as a scriptPubKey, decoding is not required.

Verification holds one 32-byte accumulator and consumes each sibling as it
arrives. Working memory is therefore constant regardless of tree size: 32 bytes
for the running node plus one 32-byte sibling at a time. This is what makes the
construction viable on constrained hardware such as a secure element.

Proof size is fixed: nonce 32 bytes, position 4 bytes, and 8 siblings of 32
bytes, for a total of 292 bytes.

### Sender-side device flow

Three operations are defined. All three are OPTIONAL for a sender that verifies
proofs in software on a general-purpose host. All three are REQUIRED for a
sender implementation running on a signing device.

#### Contact registration

The device does not store contacts in persistent memory. It authenticates a
registration record and returns it to the host, which stores it and presents it
back when needed.

```
record = { contact_name, identity_pubkey, root }
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
                  concat("BIPXXX_POR", script_pubkey, contact_name))
```

#### Proof of Recipient redemption

At signing time, for each transaction output:

```
expected = hmac_sha256(device_secret,
                       concat("BIPXXX_POR",
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
key:   PSBT_OUT_PROPRIETARY | "BIPXXX" | 0x01
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
test membership, and the sender, the party the blinding protects against, does
not hold the nonce key.

**Nonces derived from the descriptor rather than an independent seed.** In a
multisig setting, a nonce key derived from one cosigner's seed leaves the
other cosigners unable to rebuild the tree, and the failure surfaces only at
recovery time, when the missing cosigner is least likely to be reachable.
Deriving from the aggregated descriptor means any cosigner holding the
descriptor can rebuild the tree from scratch. This costs no privacy: anyone
holding the xpubs can already enumerate addresses directly, and the sender,
the party blinding protects against, holds neither the descriptor nor the
xpubs.

**HMAC rather than BIP32 child derivation.** The nonce is a blinding value,
not a curve point, so scalar multiplication buys nothing and costs
non-negligible time on a secure element. HMAC also makes the security argument
simpler: under standard PRF assumptions, revealing one nonce leaks nothing
about any other, which is the property the proof format relies on.

**Commitment to the scriptPubKey rather than the address string.** Address
encodings vary: bech32 versus bech32m, casing on chain, future encodings.
The scriptPubKey is the bytes that actually appear in the transaction, and is
what the verifier can extract unambiguously without an encoding decision.

**Placement by keyed shuffle rather than by derivation index.** If leaves sat
at their derivation index, the tree position would reveal the index, which
leaks how many addresses the recipient has used and in what order. The shuffle is
derived from the descriptor keys digest, so every wallet with the descriptor
rebuilds the same tree without revealing the permutation to the sender.

**Fisher-Yates rather than a keyed PRP.** A Feistel construction would give the
same decorrelation and constant memory. It was rejected because it must be
specified exactly: round count, bit width, endianness, and round function. A
wrong reimplementation fails silently by producing a different root with no
detectable error. For a fixed 256-leaf tree, Fisher-Yates costs one 256-byte
array and is simpler to specify.

**Ordered children rather than BIP341-style sorted siblings.** BIP341 sorts
sibling pairs because a TapTree proof needs only membership, so direction bits
are redundant and can be dropped. Here the position is transmitted regardless.
Sorting the two children would therefore save nothing and would make a single
proof verify at multiple positions, reducing the position to an unauthenticated
hint rather than a binding selector.

**Fixed 256-leaf tree.** A one-byte offset addresses every leaf in the tree,
which makes proof serving simple and keeps proofs fixed-size. Larger address
ranges are represented by building another 256-leaf tree with a later aligned
start index, not by changing the tree shape.

**No padding.** Every tree has exactly 256 real derivation slots. There is no
partial tree and no padding leaf domain in this version.

**Version in the tag strings rather than a header field.** A future revision
of this proposal changes the tag strings. Because the tag is inside the hash,
signatures and proofs under two versions are non-interchangeable by
construction. This costs zero bytes and removes a version field that could
disagree with the data it purports to describe.

**Long-lived identity key.** Without a stable identity key, tree exhaustion
would force a fresh out-of-band ceremony with every sender at a moment the
recipient does not choose, typically the moment a new payment is already pending.
Signing each root under a stable identity key means a larger tree can be
accepted automatically by any sender who stored the pubkey, converting a
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

**OPEN ITEM: must be generated from a working reference implementation.**
Hand-authored vectors will not be accepted. The vector set MUST cover, at
minimum:

- A tree with every intermediate value printed: per-leaf nonces, per-leaf
  hashes, shuffled order, every branch hash, the root, and the signed
  commitment.
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

- **BIP number.** Every tag string contains `BIPXXX` as a placeholder. The
  assigned BIP number replaces it throughout.

- **Identity key derivation path.** A long-lived identity key signs the root
  commitment at a fixed derivation path distinct from any address key.
  Candidate path (flagged for review, not normative):
  `m/<PURPOSE>'/0'/0'`, where `<PURPOSE>` is the hardened purpose number
  equal to the assigned BIP number. This path is proposed because it is
  disjoint from existing registered purposes and is recoverable from the BIP
  number alone, but it has not been reviewed against the full registered
  purpose space and MUST NOT be relied on until settled.

- **Keychain values.** The nonce input includes a 32-bit keychain identifier.
  The values for receive, change, and any descriptor-specific keychain must be
  assigned before this proposal is finalized.

- **Signature scheme.** BIP340 Schnorr is the obvious default for the root
  signature, reusing existing secure-element support. The exact message format
  is an open item. The scheme and message format MUST be fixed before this
  proposal is finalized.

- **Test vectors.** As above, MUST be generated from the reference
  implementation.

## Acknowledgements

TBD.

## Copyright

This document is licensed under the BSD 2-clause license.
