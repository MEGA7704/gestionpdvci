"""Regression checks for SQL invariants and static backend guards. Run: python -m unittest discover -s tests -v"""
import sqlite3, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
class FinancialSecurityTests(unittest.TestCase):
 def setUp(self):
  self.db=sqlite3.connect(':memory:')
  for f in sorted((ROOT/'migrations').glob('*.sql')):self.db.executescript(f.read_text())
  self.db.execute("INSERT INTO pdv_companies(id,name,email) VALUES('c','Entreprise','a@a.test')")
  self.db.execute("INSERT INTO pdv_users(id,company_id,name,email,role) VALUES('u','c','Admin','u@a.test','admin')")
  self.db.execute("INSERT INTO pdv_points_of_sale(id,company_id,name) VALUES('p','c','PDV')")
  self.db.execute("INSERT INTO pdv_accounts(id,company_id,pos_id,kind,balance) VALUES('a','c','p','cash',100)")
 def test_negative_balance_blocked(self):
  with self.assertRaises(sqlite3.IntegrityError):self.db.execute("UPDATE pdv_accounts SET balance=-1 WHERE id='a'")
 def test_single_closure_per_day(self):
  self.db.execute("INSERT INTO cash_closures(id,company_id,pos_id,business_date,actor_id) VALUES('x','c','p',date('now'),'u')")
  with self.assertRaises(sqlite3.IntegrityError):self.db.execute("INSERT INTO cash_closures(id,company_id,pos_id,business_date,actor_id) VALUES('y','c','p',date('now'),'u')")
 def test_closed_pos_rejects_new_transactions(self):
  self.db.execute("INSERT INTO cash_closures(id,company_id,pos_id,business_date,actor_id) VALUES('x','c','p',date('now'),'u')")
  with self.assertRaises(sqlite3.IntegrityError):self.db.execute("INSERT INTO pdv_transactions(id,company_id,pos_id,actor_id,type,amount) VALUES('t','c','p','u','deposit',10)")
 def test_duplicate_idempotency(self):
  q="INSERT INTO pdv_transactions(id,company_id,pos_id,actor_id,type,amount,idempotency_key) VALUES(?,?,?,?,?,?,?)"
  self.db.execute(q,('t1','c','p','u','deposit',10,'same'))
  with self.assertRaises(sqlite3.IntegrityError):self.db.execute(q,('t2','c','p','u','deposit',10,'same'))
 def test_api_guards_present(self):
  s=(ROOT/'public/_worker.js').read_text()
  for x in ['x-csrf-token','password_version','company_id','cash/close','corrections/decide','password/reset-user','password/change','SETUP_TOKEN','HttpOnly','SameSite=Lax']:
   self.assertIn(x,s)
if __name__=='__main__':unittest.main()
