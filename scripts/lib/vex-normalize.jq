# vex-normalize.jq -- re-express a VEX document in the package identifiers the
# scanners actually emit, so its statements are applied instead of ignored.
#
#   input:      the OpenVEX document (bare, already unwrapped from in-toto)
#   $packages:  scanner package inventory: [{Name, Version, SrcName, SrcVersion, PURL}]
#   output:     { vex: <normalized document>, mappings: [...], unmatched: [...] }
#
# WHY THIS EXISTS
#
# DHI VEX identifies products by Debian SOURCE package PURL:
#   pkg:deb/debian/glibc@2.41-12+deb13u3+dhi1?os_distro=trixie&os_name=debian&os_version=13
#
# Trivy and Grype match on the BINARY package they actually found:
#   pkg:deb/debian/libc6@2.41-12+deb13u3+dhi1?arch=amd64&distro=debian-13.6
#
# Different package name, different qualifiers. Neither scanner applies the
# statement -- verified: Trivy 12 -> 12 findings, Grype 6 -> 6, ignoredMatches 0.
# The vendor says "not affected"; the scanner reports the CVE anyway.
#
# WHAT THIS DOES AND DOES NOT CHANGE
#
# The vulnerability, status, justification and impact_statement of every statement
# are copied verbatim. ONLY the product identifier is rewritten, and only to
# packages the scanner reports as built FROM the source package the vendor named,
# AT a matching version. Original products are retained alongside the added ones,
# so nothing is lost if a scanner would have matched them.
#
# This is a translation, not an assessment. It never invents a status, never
# broadens a statement to another CVE, and refuses to map when versions disagree --
# an unmatched statement is reported in `unmatched` rather than guessed at.

# PURLs percent-encode '+', ':' and '~', which appear throughout Debian versions.
def urldec:
  gsub("%2B"; "+") | gsub("%2b"; "+")
  | gsub("%3A"; ":") | gsub("%3a"; ":")
  | gsub("%7E"; "~") | gsub("%7e"; "~");

def purl_name:  split("?")[0] | split("@")[0] | split("/") | .[-1] | urldec;
def purl_version:
  split("?")[0] as $p
  | if ($p | test("@")) then ($p | split("@")[1:] | join("@") | urldec) else null end;

# Debian encodes an epoch as a leading "N:" in the version, but PURL carries it as
# a separate ?epoch= qualifier -- so zlib is "1:1.3.dfsg..." in the VEX and
# "1.3.dfsg..." plus epoch=1 in the scanner PURL. Strip it from both sides.
def strip_epoch: if . == null then null else sub("^[0-9]+:"; "") end;
def norm_version: urldec | strip_epoch;

($packages // []) as $pkgs

| [ (.statements // [])[]
    | . as $stmt
    | [ (.products // [])[]
        | (if type == "object" then (.["@id"] // "") else . end) as $pid
        | select($pid != "")
        | { pid: $pid, name: ($pid | purl_name), version: ($pid | purl_version | norm_version) }
      ] as $wanted

    | [ $wanted[]
        | . as $w
        # A scanner package matches when the VEX named either its source package
        # or the binary itself, AND the versions agree once normalised.
        | [ $pkgs[]
            | select( ((.SrcName // "") == $w.name) or ((.Name // "") == $w.name) )
            | select( ((.PURL // "") | purl_version | norm_version) == $w.version )
            | { purl: .PURL, name: .Name, src: (.SrcName // null) }
          ]
        | map(select(.purl != null and .purl != ""))
      ] | add // [] | unique_by(.purl) as $matched

    | { statement: $stmt, wanted: $wanted, matched: $matched }
  ] as $work

| {
    vex: ( . + {
      statements: [ $work[]
        | .statement + {
            products: (
              # Original products first, then the scanner-visible ones. Additive:
              # if a scanner would already have matched, that path still works.
              ((.statement.products // []) | map(if type == "object" then . else {"@id": .} end))
              + ( .matched | map({"@id": .purl}) )
              | unique_by(.["@id"])
            )
          }
      ]
    }),

    mappings: [ $work[] | select((.matched | length) > 0)
                | { vulnerability: (.statement.vulnerability.name // .statement.vulnerability),
                    from: [.wanted[].name] | unique,
                    to: [.matched[] | .name],
                    purls: [.matched[].purl] } ],

    unmatched: [ $work[] | select((.matched | length) == 0)
                 | { vulnerability: (.statement.vulnerability.name // .statement.vulnerability),
                     wanted: [.wanted[] | {name, version}] } ]
  }
