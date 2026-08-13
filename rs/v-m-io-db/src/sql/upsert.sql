INSERT INTO entries (
  class,
  key,
  modified_at_micros,
  expires_at_micros,
  metadata
)
VALUES (
  ?1, -- class
  ?2, -- key
  ?3, -- modified_at_micros
  ?4, -- expires_at_micros
  ?5 -- metadata
)
ON CONFLICT(class, key) DO UPDATE SET
  modified_at_micros = excluded.modified_at_micros,
  expires_at_micros = excluded.expires_at_micros,
  metadata          = excluded.metadata
