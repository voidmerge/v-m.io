-- blob ids belonging to the batch of entries that prune_expired.sql will
-- delete. both statements must select the same batch, hence the identical
-- (and deterministic, since class/key is the primary key) subquery.
SELECT
  blob_id
FROM entry_file_chunks
WHERE (class, key) IN (
  SELECT class, key
  FROM entries
  WHERE expires_at_micros IS NOT NULL
    AND expires_at_micros <= ?1
  ORDER BY expires_at_micros, class, key
  LIMIT ?2
)
