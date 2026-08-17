# expand-config.jq -- expand sync-config.yaml (converted to JSON) into the
# flat allow list the pipeline iterates over:
#
#   [ { repo, tag, requireVex, hold, note }, ... ]
#
# Rules, asserted by tests/test-expand-config.sh:
#   - a tag entry may be a plain string or a mapping with {tag, requireVex,
#     hold, note}
#   - requireVex and hold inherit: tag-level setting wins over image-level
#     wins over false -- including an explicit tag-level `false` overriding an
#     image-level `true` (which a naive `//` chain would silently ignore,
#     because jq's // treats false as absent)
#   - malformed input fails LOUDLY: a config typo must stop the poll, not
#     silently shrink the allow list. Errors cover: missing images array,
#     an image without repo or without tags, a mapping tag entry without
#     .tag, non-boolean requireVex/hold, and duplicate repo:tag pairs.

def fail(msg): error("sync-config invalid: " + msg);

# Tri-state inheritance that respects explicit false.
def setting($t; $img; key):
  if ($t | has(key)) then $t[key]
  elif ($img | has(key)) then $img[key]
  else false end
  | if type != "boolean" then
      fail(key + " must be true or false (got " + (tojson) + ")")
    else . end;

if type != "object" or ((.images? | type) != "array") then
  fail("top level must be a mapping with an images list")
elif (.images | length) == 0 then
  fail("images list is empty -- an empty allow list should be an explicit decision, delete the poll instead")
else
  [ .images[]
    | . as $img
    | if (($img.repo? // "") | tostring) == "" then fail("an images entry has no repo") else . end
    | if (($img.tags? | type) != "array") or (($img.tags | length) == 0) then
        fail("image " + $img.repo + " has no tags list")
      else . end
    | $img.tags[]
    | (if type == "string" then { tag: . }
       elif type == "object" then .
       else fail("image " + $img.repo + " has a tag entry that is neither a string nor a mapping")
       end) as $t
    | if (($t.tag? // "") | tostring) == "" then
        fail("image " + $img.repo + " has a mapping tag entry without .tag")
      else . end
    | { repo: $img.repo,
        tag: ($t.tag | tostring),
        requireVex: setting($t; $img; "requireVex"),
        hold: setting($t; $img; "hold"),
        note: ($t.note // null) }
  ]
  | ( group_by(.repo + ":" + .tag)
      | map(select(length > 1) | .[0].repo + ":" + .[0].tag) ) as $dups
  | if ($dups | length) > 0 then
      fail("duplicate entries: " + ($dups | join(", ")))
    else . end
end
