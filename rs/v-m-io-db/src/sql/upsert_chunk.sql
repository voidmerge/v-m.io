INSERT INTO entry_file_chunks (
  class,
  key,
  idx,
  blob_id,
  hash,
  nonce,
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
  ?6, -- nonce
  ?7, -- tag
  ?8, -- size
  ?9  -- is_final
)
ON CONFLICT(class, key, idx) DO UPDATE SET
  blob_id = excluded.blob_id,
  hash = excluded.hash,
  nonce = excluded.nonce,
  tag = excluded.tag,
  size = excluded.size,
  is_final = excluded.is_final;
