SELECT
  modified_at_micros,
  expires_at_micros,
  metadata,
  (
    SELECT COUNT(idx)
    FROM entry_file_chunks
    WHERE class = entries.class AND key = entries.key
  ) AS chunk_count
FROM entries
WHERE class = ?1
  AND key = ?2
