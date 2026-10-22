ALTER TABLE pdv_companies ADD COLUMN status TEXT NOT NULL DEFAULT 'active';
ALTER TABLE pdv_transactions ADD COLUMN idempotency_key TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS ux_tx_idempotency ON pdv_transactions(company_id,idempotency_key);
CREATE TABLE IF NOT EXISTS pdv_subscription_requests(id TEXT PRIMARY KEY,company_id TEXT NOT NULL,plan TEXT NOT NULL,phone TEXT NOT NULL,transaction_id TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'pending',created_at TEXT DEFAULT CURRENT_TIMESTAMP,reviewed_at TEXT);
CREATE INDEX IF NOT EXISTS ix_assign_user ON pdv_pos_user_assignments(user_id,pos_id);
CREATE INDEX IF NOT EXISTS ix_tx_pos_time ON pdv_transactions(company_id,pos_id,created_at DESC);
