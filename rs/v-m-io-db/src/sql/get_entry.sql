SELECT
  modified_at_micros,
  expires_at_micros,
  metadata
FROM entries
WHERE class = ?1
  AND key = ?2
