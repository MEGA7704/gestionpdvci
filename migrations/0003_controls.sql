CREATE TABLE IF NOT EXISTS cash_closures(id TEXT PRIMARY KEY,company_id TEXT NOT NULL,pos_id TEXT NOT NULL,business_date TEXT NOT NULL,actor_id TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'closed',observations TEXT,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,UNIQUE(company_id,pos_id,business_date));
CREATE TABLE IF NOT EXISTS cash_closure_lines(id TEXT PRIMARY KEY,closure_id TEXT NOT NULL,account_id TEXT NOT NULL,expected INTEGER NOT NULL,observed INTEGER NOT NULL CHECK(observed>=0),difference INTEGER NOT NULL,FOREIGN KEY(closure_id) REFERENCES cash_closures(id));
CREATE TABLE IF NOT EXISTS correction_requests(id TEXT PRIMARY KEY,company_id TEXT NOT NULL,transaction_id TEXT NOT NULL,requester_id TEXT NOT NULL,reason TEXT NOT NULL,status TEXT NOT NULL CHECK(status IN ('pending','approved','rejected')),approver_id TEXT,reversal_transaction_id TEXT,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,decided_at TEXT,FOREIGN KEY(transaction_id) REFERENCES transactions(id));
CREATE INDEX IF NOT EXISTS ix_closures_company_date ON cash_closures(company_id,business_date DESC);
CREATE INDEX IF NOT EXISTS ix_corrections_company_status ON correction_requests(company_id,status,created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS ux_correction_reversal ON correction_requests(reversal_transaction_id) WHERE reversal_transaction_id IS NOT NULL;
CREATE TRIGGER IF NOT EXISTS block_post_closure BEFORE INSERT ON transactions
WHEN EXISTS (SELECT 1 FROM cash_closures c WHERE c.company_id=NEW.company_id AND c.pos_id=NEW.pos_id AND c.business_date=date('now') AND c.status='closed')
BEGIN SELECT RAISE(ABORT,'Caisse clôturée'); END;
