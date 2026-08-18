SELECT
  hash,
  tag,
  size,
  is_final
FROM entry_file_chunks
WHERE class = ?1
  AND key = ?2
  AND idx = ?3
