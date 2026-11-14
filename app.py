import os, sqlite3, secrets, time, logging
from functools import wraps
from flask import Flask, request, session, redirect, render_template_string, abort
from werkzeug.security import generate_password_hash, check_password_hash
app = Flask(__name__)
app.config.update(SECRET_KEY=os.environ.get('SECRET_KEY') or secrets.token_hex(32), SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax', SESSION_COOKIE_SECURE=os.environ.get('HTTPS')=='1', MAX_CONTENT_LENGTH=16384)
DB=os.environ.get('NOTES_DB','notes.sqlite3')
logging.basicConfig(level=logging.INFO)
def db():
    c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; return c
with db() as c:
    c.executescript('CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT UNIQUE, password TEXT); CREATE TABLE IF NOT EXISTS notes(id INTEGER PRIMARY KEY, owner INTEGER, title TEXT, body TEXT); CREATE TABLE IF NOT EXISTS attempts(name TEXT, at REAL);')
PAGE='''<!doctype html><html><head><title>Student Notes</title><style>body{font:17px system-ui;background:#eef3f7;color:#172b40;max-width:800px;margin:50px auto;padding:20px}main{background:white;padding:32px;border-radius:16px}input,textarea{display:block;width:95%;padding:12px;margin:12px 0;border:1px solid #aab9c6;border-radius:6px}button{background:#175c74;color:white;padding:10px 18px;border:0;border-radius:6px}article{border-bottom:1px solid #ddd;padding:15px 0}a{color:#175c74}</style></head><body><main><h1>Student Notes</h1><p>Your private study space</p>{% if error %}<p role="alert">{{error}}</p>{% endif %}{% if not user %}<form method="post"><input type="hidden" name="csrf" value="{{csrf}}"><label>Username<input name="name" required maxlength="40"></label><label>Password<input name="password" type="password" required></label><button name="action" value="login">Log in</button> <button name="action" value="register">Register</button><p>Registration passwords must have at least 12 characters.</p></form>{% else %}<p>Signed in as {{user}}</p><form method="post" action="/logout"><input type="hidden" name="csrf" value="{{csrf}}"><button>Log out</button></form><h2>Create a note</h2><form method="post" action="/notes"><input type="hidden" name="csrf" value="{{csrf}}"><input name="title" placeholder="Title" required maxlength="120"><textarea name="body" placeholder="Note" required maxlength="5000"></textarea><button>Save note</button></form>{% for n in notes %}<article><form method="post" action="/notes/{{n.id}}"><input type="hidden" name="csrf" value="{{csrf}}"><label>Title<input name="title" value="{{n.title}}" required maxlength="120"></label><label>Note<textarea name="body" required maxlength="5000">{{n.body}}</textarea></label><button name="action" value="edit">Save changes</button> <button name="action" value="delete">Delete</button></form></article>{% endfor %}{% endif %}</main></body></html>'''
@app.before_request
def protect():
    session.setdefault('csrf',secrets.token_hex(32))
    if request.method=='POST' and not secrets.compare_digest(session['csrf'],request.form.get('csrf','')): abort(400)
@app.after_request
def headers(r):
    r.headers['Content-Security-Policy']="default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; form-action 'self'"
    r.headers['X-Content-Type-Options']='nosniff'; r.headers['Cache-Control']='no-store'; return r
def auth(f):
    @wraps(f)
    def wrapper(*a,**k):
        if not session.get('uid'): abort(401)
        return f(*a,**k)
    return wrapper
@app.route('/',methods=['GET','POST'])
def home():
    error=None
    if request.method=='POST':
        name=request.form.get('name','').strip(); password=request.form.get('password',''); action=request.form.get('action')
        with db() as c:
            c.execute('DELETE FROM attempts WHERE at < ?', (time.time()-300,))
            count=c.execute('SELECT count(*) FROM attempts WHERE name=?',(name,)).fetchone()[0]
            if count>=5: return 'Too many attempts. Try again in five minutes.',429
            if action=='register':
                if not name.isalnum() or not 3<=len(name)<=40 or not 12<=len(password)<=128: error='Use a 3–40 character alphanumeric username and a 12–128 character password.'
                else:
                    try: c.execute('INSERT INTO users(name,password) VALUES (?,?)',(name,generate_password_hash(password, method='pbkdf2:sha256:1000000'))); error='Account created. Please log in.'
                    except sqlite3.IntegrityError: error='Registration could not be completed.'
            elif action=='login':
                u=c.execute('SELECT * FROM users WHERE name=?',(name,)).fetchone()
                if u and check_password_hash(u['password'],password):
                    session.clear(); session.update(uid=u['id'],name=u['name'],csrf=secrets.token_hex(32)); return redirect('/')
                c.execute('INSERT INTO attempts VALUES (?,?)',(name,time.time())); logging.warning('Authentication failed'); error='Invalid credentials.'
    with db() as c: notes=c.execute('SELECT * FROM notes WHERE owner=? ORDER BY id DESC',(session.get('uid'),)).fetchall()
    return render_template_string(PAGE,error=error,user=session.get('name'),csrf=session['csrf'],notes=notes)
@app.post('/logout')
def logout(): session.clear(); return redirect('/')
@app.post('/notes')
@auth
def create():
    title,body=content()
    with db() as c: c.execute('INSERT INTO notes(owner,title,body) VALUES (?,?,?)',(session['uid'],title,body))
    return redirect('/')
def content():
    title=request.form.get('title','').strip(); body=request.form.get('body','').strip()
    if not 1<=len(title)<=120 or not 1<=len(body)<=5000: abort(400)
    return title,body
@app.post('/notes/<int:nid>')
@auth
def change(nid):
    with db() as c:
        if not c.execute('SELECT id FROM notes WHERE id=? AND owner=?',(nid,session['uid'])).fetchone():
            logging.warning('Note access denied user=%s note=%s',session['uid'],nid); abort(404)
        if request.form.get('action')=='delete': c.execute('DELETE FROM notes WHERE id=? AND owner=?',(nid,session['uid']))
        else:
            title,body=content(); c.execute('UPDATE notes SET title=?,body=? WHERE id=? AND owner=?',(title,body,nid,session['uid']))
    return redirect('/')
if __name__=='__main__': app.run(host='127.0.0.1',port=5000)
