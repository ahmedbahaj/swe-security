import os,tempfile,unittest
os.environ['NOTES_DB']=tempfile.mktemp(suffix='.sqlite3')
from app import app,db
class SecurityTests(unittest.TestCase):
 def setUp(self):
  self.a=app.test_client(); self.b=app.test_client()
  with db() as c:
   c.executescript('DELETE FROM notes; DELETE FROM users; DELETE FROM attempts;')
 def post(self,c,url,data):
  c.get('/')
  with c.session_transaction() as s: data['csrf']=s['csrf']
  return c.post(url,data=data)
 def login(self,c,name):
  self.post(c,'/',dict(action='register',name=name,password='long-test-password'))
  self.post(c,'/',dict(action='login',name=name,password='long-test-password'))
 def test_isolation_and_crud(self):
  self.login(self.a,'alice'); self.login(self.b,'bobby')
  self.assertEqual(self.post(self.a,'/notes',dict(title='Private',body='secret')).status_code,302)
  with db() as c: nid=c.execute('SELECT id FROM notes').fetchone()[0]
  self.assertNotIn(b'secret',self.b.get('/').data)
  self.assertEqual(self.post(self.b,f'/notes/{nid}',dict(action='delete')).status_code,404)
  self.assertEqual(self.post(self.a,f'/notes/{nid}',dict(title='Updated',body='new')).status_code,302)
  self.assertIn(b'Updated',self.a.get('/').data)
  self.post(self.a,f'/notes/{nid}',dict(action='delete'))
  self.assertNotIn(b'Updated',self.a.get('/').data)
 def test_csrf_auth_and_escaping(self):
  self.assertEqual(self.a.post('/notes',data={}).status_code,400)
  self.assertEqual(self.post(self.a,'/notes',dict(title='a',body='b')).status_code,401)
  self.login(self.a,'alice'); self.post(self.a,'/notes',dict(title='<script>',body='<script>alert(1)</script>'))
  self.assertNotIn(b'<script>',self.a.get('/').data)
  self.assertIn(b'&lt;script&gt;',self.a.get('/').data)
  with db() as c: self.assertNotEqual(c.execute('SELECT password FROM users').fetchone()[0],'long-test-password')
 def test_throttle_and_validation(self):
  for _ in range(5): self.post(self.a,'/',dict(action='login',name='nobody',password='wrong'))
  self.assertEqual(self.post(self.a,'/',dict(action='login',name='nobody',password='wrong')).status_code,429)
  self.login(self.b,'bobby'); self.assertEqual(self.post(self.b,'/notes',dict(title='',body='x')).status_code,400)
if __name__=='__main__': unittest.main()
