INSERT INTO entry_file_chunks (
  class,
  key,
  idx,
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
  ?4, -- hash
  ?5, -- nonce
  ?6, -- tag
  ?7, -- size
  ?8  -- is_final
)
ON CONFLICT(class, key, idx) DO UPDATE SET
  hash = excluded.hash,
  nonce = excluded.hash,
  tag = excluded.hash,
  size = excluded.hash,
  is_final = excluded.hash;
