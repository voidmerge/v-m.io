-- delete a bounded batch of expired entries. chunk rows follow via the
-- entry_file_chunks ON DELETE CASCADE foreign key.
DELETE FROM entries
WHERE (class, key) IN (
  SELECT class, key
  FROM entries
  WHERE expires_at_micros IS NOT NULL
    AND expires_at_micros <= ?1
  ORDER BY expires_at_micros, class, key
  LIMIT ?2
)
