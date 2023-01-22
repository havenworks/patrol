-- migrate:up
CREATE TABLE user_tokens (
  value TEXT NOT NULL PRIMARY KEY,
  valid BOOLEAN NOT NULL DEFAULT TRUE,

  user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE
);

CREATE INDEX user_tokens_user_id ON user_tokens (user_id);

-- migrate:down
DROP TABLE IF EXISTS user_tokens;
