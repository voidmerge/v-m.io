SELECT count(idx) FROM entry_file_chunks
WHERE class = ?1 AND key = ?2;
