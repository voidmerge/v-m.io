INSERT INTO entry_file_chunks (
  class,
  key,
  idx,
  blob_id,
  hash,
  tag,
  size,
  is_final
)
VALUES (
  ?1, -- class
  ?2, -- key
  ?3, -- idx
  ?4, -- blob_id
  ?5, -- hash
  ?6, -- tag
  ?7, -- size
  ?8  -- is_final
)
ON CONFLICT(class, key, idx) DO UPDATE SET
  blob_id = excluded.blob_id,
  hash = excluded.hash,
  tag = excluded.tag,
  size = excluded.size,
  is_final = excluded.is_final;
