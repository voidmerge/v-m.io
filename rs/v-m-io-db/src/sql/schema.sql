CREATE TABLE IF NOT EXISTS entries (
  class TEXT NOT NULL,
  key TEXT NOT NULL,
  -- modified_at_micros must be unique so paging by filter range works
  -- if you get a conflict, adjust up or down by several microseconds
  modified_at_micros INTEGER UNIQUE NOT NULL,
  expires_at_micros INTEGER NULL,
  metadata BLOB NULL,
  PRIMARY KEY (class, key)
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS entries_sort_idx ON entries (class, modified_at_micros);
CREATE INDEX IF NOT EXISTS entries_expires_idx ON entries (expires_at_micros)
  WHERE expires_at_micros IS NOT NULL;

CREATE TABLE IF NOT EXISTS entry_file_chunks (
  class TEXT NOT NULL,
  key TEXT NOT NULL,
  idx INTEGER NOT NULL,
  hash BLOB NOT NULL,
  nonce BLOB NOT NULL,
  tag BLOB NOT NULL,
  size INT NOT NULL,
  last BOOLEAN NOT NULL DEFAULT FALSE,

  PRIMARY KEY (class, key, idx),
  FOREIGN KEY (class, key) REFERENCES entries (class, key)
    ON DELETE CASCADE
    ON UPDATE CASCADE
) WITHOUT ROWID;
