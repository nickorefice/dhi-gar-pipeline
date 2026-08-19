# METADATA
# title: Image must be a Docker Hardened Image
# description: |
#   Asserts that the image under evaluation carries Docker's own DHI markers, so
#   only hardened images can reach the production registry.
#
#   WHY THIS SHAPE, AND NOT A BASE-IMAGE ALLOWLIST. The obvious way to write
#   "only DHI reaches prod" is to gate the BASE image -- Scout even ships a
#   built-in `approved-base-images` policy for exactly that. It does not work
#   here, for a reason worth recording: a DHI HAS NO BASE IMAGE. dhi-node is not
#   built FROM anything; its history contains no rootfs import, and it is
#   assembled from hardened .deb packages fetched from dhi.io. Its SLSA
#   provenance lists exactly two container dependencies -- dhi/build (the build
#   toolchain) and dhi/scout-sbom-indexer -- and neither is a runtime base.
#
#   So `approved-base-images` reports "No data" on every tag this pipeline
#   syncs, and a hand-written "some dependency starts with dhi" test would pass
#   by matching the BUILD TOOLCHAIN -- a gate that is green for a reason
#   unrelated to what it claims to check. That is the same class of failure as
#   a VEX document that silently suppresses nothing: the check runs, nothing
#   errors, and the result means less than it appears to.
#
#   org.opencontainers.image.base.name is not an alternative either. BuildKit has
#   never populated it (moby/buildkit#2756, open since 2022); it is absent on
#   every DHI image AND on stock library images, so gating on it fails closed
#   on 100% of legitimate traffic.
#
#   com.docker.dhi.* is what DHI actually records. It appears as both config
#   labels and manifest annotations, was observed on 5/5 mirrored DHI images and
#   0/3 non-DHI controls, and -- because annotations live inside the
#   digest-covered manifest bytes -- a digest-preserving copy provably cannot
#   strip it. That is the same immutability this pipeline already asserts at
#   every hop.
#
#   SCOPE. These markers are vendor-asserted metadata, not a cryptographic
#   proof: anyone can label an image com.docker.dhi.name=dhi/node. This policy
#   is therefore a POLICY gate, not a trust root, and it is deliberately ordered
#   AFTER the verify gate, which is what establishes that the signed
#   attestations are present and bound to this digest.
# custom:
#   name: dhi-provenance
#   result_type: generic
#   weight: 20
#   not_compliant_title: Not a Docker Hardened Image
#   details_order:
#     - marker
#     - value
#     - source
package docker.scout

import rego.v1

default pass := false

pass if count(violation) == 0

# --------------------------------------------------------------------------
# Configuration, overridable via --policy-config.
#
#   {"policies": [{"name": "dhi-provenance",
#                  "config": {"required_name_prefix": "dhi/",
#                             "require_distro": true}}]}
#
# required_name_prefix is "dhi/" -- NOT "dhi-". The mirror repository is named
# <org>/dhi-node, but the marker INSIDE the image is com.docker.dhi.name =
# "dhi/node", with a slash. Gating on "dhi-" would reject every genuine DHI.
# --------------------------------------------------------------------------
# When no policy-config is supplied at all, `data.config` is UNDEFINED, and
# object.get on an undefined first argument is itself undefined -- which would
# propagate into the guards below and let a rule fire, or not fire, for reasons
# having nothing to do with the image. A `default` rule pins it to {} instead.
#
# Do NOT "fix" this by reading object.get(data, "config", {}): referencing all of
# `data` pulls this package's own rules into the reference graph and OPA rejects
# the policy outright with rego_recursion_error (config -> violation -> config).
default config := {}

config := data.config

required_prefix := object.get(config, "required_name_prefix", "dhi/")

require_distro := object.get(config, "require_distro", true)

# --------------------------------------------------------------------------
# Marker extraction.
#
# Read config labels FIRST, then manifest annotations. DHI populates both, but
# they are independent carriers: a re-tag that rewrites the config would still
# have to preserve the annotations to keep the digest, and vice versa. Checking
# both means either survivor satisfies the gate, and the report records which
# one answered.
# --------------------------------------------------------------------------
labels := object.get(input, ["source", "image", "config", "config", "Labels"], {})

annotations := object.get(input, ["source", "image", "manifest", "annotations"], {})

sources := [
	{"where": "config.Labels", "values": labels},
	{"where": "manifest.annotations", "values": annotations},
	{"where": "input.deep-scan", "values": deep},
]

# LAST-RESORT FALLBACK, and the reason is honest uncertainty: the two paths above
# come from Docker's documentation of the policy input document, not from a
# verified live evaluation -- `docker scout policy` requires network access to
# api.dso.docker.com, so the exact nesting could not be confirmed offline. If
# either path is wrong, a gate keyed only on them would reject EVERY genuine DHI,
# which is the worst possible failure for a policy whose job is to admit them.
#
# So the marker is also looked for anywhere in the input document. This is safe
# rather than sloppy: every value in the input derives from the image's own
# metadata, so there is no separate untrusted region a marker could hide in. The
# violation detail records WHICH source answered, so the first real run shows
# whether the documented paths worked -- and if this fallback is what matched,
# that is a signal to tighten the paths above, not to leave it as the mechanism.
deep[k] := v if {
	some obj
	walk(input, [_, obj])
	is_object(obj)
	some k, v in obj
	startswith(k, "com.docker.dhi.")
	is_string(v)
}

# Ordered candidate list, so the verdict is deterministic rather than dependent
# on set-iteration order.
name_candidates := [c |
	some s in sources
	v := object.get(s.values, "com.docker.dhi.name", "")
	v != ""
	c := {"where": s.where, "value": v}
]

distro_candidates := [c |
	some s in sources
	v := object.get(s.values, "com.docker.dhi.distro", "")
	v != ""
	c := {"where": s.where, "value": v}
]

dhi_name := name_candidates[0] if count(name_candidates) > 0

# --------------------------------------------------------------------------
# Violations
# --------------------------------------------------------------------------

# 1. No marker anywhere. Fails CLOSED: an image that carries no DHI marker is
#    treated as not a DHI, never as "probably fine".
violation contains v if {
	count(name_candidates) == 0
	v := {
		"message": "no com.docker.dhi.name marker anywhere in the image metadata -- this is not a Docker Hardened Image",
		"detail": {
			"marker": "com.docker.dhi.name",
			"value": "<absent>",
			"source": "checked config.Labels, manifest.annotations, and the whole input document",
		},
		"remediation": "Sync only images mirrored from the Docker Hardened Images catalog. If this IS a DHI, run the inspect-referrers workflow and confirm the mirror preserved the manifest annotations.",
	}
}

# 2. Marker present but not a DHI name.
violation contains v if {
	not startswith(dhi_name.value, required_prefix)
	v := {
		"message": sprintf("com.docker.dhi.name is %q, which does not start with %q -- this is not a Docker Hardened Image", [dhi_name.value, required_prefix]),
		"detail": {
			"marker": "com.docker.dhi.name",
			"value": dhi_name.value,
			"source": dhi_name.where,
		},
		"remediation": sprintf("Only images whose com.docker.dhi.name begins with %q may be promoted.", [required_prefix]),
	}
}

# 3. A DHI name with no distro marker. Guarded on the name being present so a
#    plain non-DHI image produces ONE clear violation instead of two, but a
#    half-populated marker set still gets flagged -- that shape suggests
#    hand-applied labels rather than a real DHI.
violation contains v if {
	require_distro
	count(name_candidates) > 0
	count(distro_candidates) == 0
	v := {
		"message": sprintf("com.docker.dhi.name is %q but com.docker.dhi.distro is absent -- incomplete DHI marker set", [dhi_name.value]),
		"detail": {
			"marker": "com.docker.dhi.distro",
			"value": "<absent>",
			"source": "checked config.Labels, manifest.annotations, and the whole input document",
		},
		"remediation": "A genuine DHI carries both markers. Verify the image really came from the DHI catalog rather than having the name label applied by hand.",
	}
}
