# classify.jq -- turn an OCI referrers index into a classified artifact inventory.
#
#   input:  the referrers index (an OCI image index; .manifests[] are descriptors)
#   --slurpfile / --argfile $types: attestation-types.json
#   output: { artifacts: [...], groupsPresent: [...], groupsMissing: [...] }
#
# Classification order matters: attestation-types.json lists specific classes
# before the generic in-toto/Docker fallback, and we take the first match, so a
# descriptor carrying both a generic artifactType and a specific predicate
# annotation is classified by its predicate.

# The predicate type can arrive under several annotation keys depending on which
# tool attached the referrer -- or under none of them.
#
# $deep is a { "<descriptor digest>": "<predicate type>" } map supplied by
# classify_referrers_deep() after fetching payloads. It is consulted FIRST and is
# authoritative: an in-toto Statement carries its predicateType inside the signed
# payload, which is a stronger claim than any unsigned descriptor annotation, and
# is frequently the only place it appears at all. Verified against real regctl
# output -- a referrer with artifactType application/vnd.in-toto+json and no
# annotations whatsoever still resolves to https://slsa.dev/provenance/v1 here,
# where a descriptor-only classifier would report provenance as missing and fail
# the gate on a perfectly valid attestation.
def predicate_of:
  ($deep[.digest] // null) as $resolved
  | if $resolved != null then $resolved
    else
      (.annotations // {}) as $a
      | $a["in-toto.io/predicate-type"]
        // $a["dev.sigstore.cosign/predicate-type"]
        // $a["org.opencontainers.artifact.predicate-type"]
        // $a["vnd.docker.reference.type"]
        // null
    end;

def title_of: (.annotations // {})["org.opencontainers.image.title"] // null;
def created_of: (.annotations // {})["org.opencontainers.image.created"] // null;

# A class matches if the descriptor's artifactType is listed exactly, or if its
# predicate type starts with one of the listed predicate prefixes (so versioned
# URIs like .../provenance/v1 match the unversioned prefix).
def matches($d):
  ( ($d.artifactType // "") as $at
    | ($at != "") and ((.artifactTypes // []) | any(. == $at)) )
  or
  ( ($d | predicate_of) as $pt
    | ($pt != null) and ((.predicateTypes // []) | any(. as $p | $pt | startswith($p))) );

def classify($d):
  ( $types.classes | map(select(matches($d))) | .[0] ) // null;

( [ (.manifests // [])[]
    | . as $d
    | (classify($d)) as $c
    | {
        digest:        $d.digest,
        mediaType:     $d.mediaType,
        size:          ($d.size // null),
        artifactType:  ($d.artifactType // null),
        predicateType: ($d | predicate_of),
        title:         ($d | title_of),
        created:       ($d | created_of),
        class:         ($c.id // "unclassified"),
        label:         ($c.label // "unclassified"),
        group:         ($c.requiredGroup // null),
        evidenceFilename: ($c.evidenceFilename // null),
        # True when this descriptor's type was only knowable by fetching its
        # payload. Recorded so verify-report.json shows how a claim was
        # established, not merely that it was.
        deepResolved:  (($deep[$d.digest] // null) != null)
      }
  ] ) as $artifacts

| ( $artifacts | map(select(.group != null) | .group) | unique ) as $present

# requiredGroups fail the gate. expectedGroups only warn, because their presence
# is a property of the upstream image rather than of the copy: OpenVEX ships on
# debian-based DHI tags and not on alpine ones, so requiring it would fail every
# Alpine image for something the pipeline neither caused nor can fix.
#
# REQUIRE_VEX=1 promotes vex to a hard requirement for a customer whose policy
# demands it -- the choice belongs to policy, not to this file.
| ( ($types.requiredGroups // [])
    + (if ($requireVex // false) then ["vex"] else [] end) | unique ) as $required
| ( $required - $present ) as $missing
| ( (($types.expectedGroups // []) - $required) - $present ) as $expectedMissing

| {
    artifacts:     $artifacts,
    total:         ($artifacts | length),
    groupsPresent: $present,
    groupsRequired: $required,
    groupsMissing: $missing,
    groupsExpectedMissing: $expectedMissing,
    unclassified:  ($artifacts | map(select(.class == "unclassified")) | length),
    deepResolvedCount: ($artifacts | map(select(.deepResolved)) | length)
  }
