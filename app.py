# ══════════════════════════════════════════════════════════════════════════════
# FINDXPERT v2.1 — SISTEMA COMPLETO
# Xpert Labs LLC · Flask + SQLite · IRS 2025
# Puerto: 5050 (evita conflicto con AirPlay en macOS)
# ══════════════════════════════════════════════════════════════════════════════
import os, json, secrets, logging
from datetime import datetime, timedelta
from functools import wraps

from dotenv import load_dotenv
load_dotenv()

from flask import (Flask, request, jsonify, send_from_directory,
                   send_file, session as flask_session)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (LoginManager, UserMixin, current_user,
                         login_user, logout_user, login_required)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

logging.basicConfig(level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s')
log = logging.getLogger('findxpert')

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def _secret_key():
    k = os.environ.get('SECRET_KEY')
    if not k:
        k = secrets.token_hex(32)
        log.warning('⚠️  SECRET_KEY no configurada — usando clave temporal')
    return k

app = Flask(__name__, static_folder='static', template_folder='templates')
app.config.update(
    SECRET_KEY                 = _secret_key(),
    SQLALCHEMY_DATABASE_URI    = os.environ.get('DATABASE_URL',
                                     f'sqlite:///{BASE_DIR}/findxpert.db'),
    SQLALCHEMY_TRACK_MODIFICATIONS = False,
    SESSION_COOKIE_HTTPONLY    = True,
    SESSION_COOKIE_SAMESITE    = 'Lax',
    SESSION_COOKIE_SECURE      = False,
    SESSION_COOKIE_NAME        = 'fx_sess',
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8),
    WTF_CSRF_ENABLED           = False,
    MAX_CONTENT_LENGTH         = 16 * 1024 * 1024,
    UPLOAD_FOLDER              = os.path.join(BASE_DIR, 'uploads'),
)

db      = SQLAlchemy(app)
csrf    = CSRFProtect(app)
limiter = Limiter(app=app, key_func=get_remote_address,
                  default_limits=[], storage_uri='memory://',
                  strategy='fixed-window')
lm      = LoginManager(app)
lm.session_protection = 'basic'

@lm.unauthorized_handler
def _unauth():
    return jsonify({'error': 'Authentication required'}), 401

# ══════════════════════════════════════════════════════════════════════════════
# MODELS
# ══════════════════════════════════════════════════════════════════════════════
class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id            = db.Column(db.Integer, primary_key=True)
    email         = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    full_name     = db.Column(db.String(255), nullable=False)
    role          = db.Column(db.String(20), default='user')
    is_active     = db.Column(db.Boolean, default=True)
    state         = db.Column(db.String(50), default='Texas')
    filing_status = db.Column(db.String(20), default='single')
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)
    last_login    = db.Column(db.DateTime)
    incomes       = db.relationship('Income',  backref='owner', lazy='dynamic',
                                    cascade='all,delete-orphan')
    receipts      = db.relationship('Receipt', backref='owner', lazy='dynamic',
                                    cascade='all,delete-orphan')

    def set_password(self, pw):
        self.password_hash = generate_password_hash(
            pw, method='pbkdf2:sha256', salt_length=16)

    def check_password(self, pw):
        return check_password_hash(self.password_hash, pw)

    def pub(self):
        return {'id': self.id, 'name': self.full_name, 'email': self.email,
                'state': self.state, 'filing_status': self.filing_status,
                'role': self.role}


class Income(db.Model):
    __tablename__ = 'incomes'
    id          = db.Column(db.Integer, primary_key=True)
    user_id     = db.Column(db.Integer, db.ForeignKey('users.id'),
                            nullable=False, index=True)
    source      = db.Column(db.String(255), nullable=False)
    amount      = db.Column(db.Float, nullable=False)
    date        = db.Column(db.String(20), nullable=False)
    invoice_num = db.Column(db.String(100), default='')
    tax_year    = db.Column(db.Integer, default=2025)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {'id': self.id, 'source': self.source, 'amount': self.amount,
                'date': self.date, 'invoice_num': self.invoice_num,
                'tax_year': self.tax_year}


class Receipt(db.Model):
    __tablename__ = 'receipts'
    id             = db.Column(db.Integer, primary_key=True)
    user_id        = db.Column(db.Integer, db.ForeignKey('users.id'),
                               nullable=False, index=True)
    vendor         = db.Column(db.String(255), default='')
    amount         = db.Column(db.Float, nullable=False)
    date           = db.Column(db.String(20), nullable=False)
    category       = db.Column(db.String(100), nullable=False, default='Other')
    deductible_pct = db.Column(db.Integer, default=100)
    notes          = db.Column(db.Text, default='')
    file_url       = db.Column(db.Text, default='')
    ai_confidence  = db.Column(db.Float, default=0.0)
    ai_raw         = db.Column(db.Text, default='')
    tax_year       = db.Column(db.Integer, default=2025)
    created_at     = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {'id': self.id, 'vendor': self.vendor, 'amount': self.amount,
                'date': self.date, 'category': self.category,
                'deductible_pct': self.deductible_pct, 'notes': self.notes,
                'file_url': self.file_url, 'ai_confidence': self.ai_confidence,
                'tax_year': self.tax_year}


class AuditLog(db.Model):
    __tablename__ = 'audit_log'
    id      = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    action  = db.Column(db.String(100))
    ip      = db.Column(db.String(45))
    success = db.Column(db.Boolean, default=True)
    note    = db.Column(db.Text)
    ts      = db.Column(db.DateTime, default=datetime.utcnow)

# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════
def audit(action, success=True, note=None):
    try:
        uid = current_user.id if current_user.is_authenticated else None
        db.session.add(AuditLog(user_id=uid, action=action,
                                ip=request.remote_addr,
                                success=success, note=note))
        db.session.commit()
    except Exception as e:
        log.error(f'Audit write failed: {e}')


def owned(Model, id_param='item_id'):
    """Anti-IDOR: verifica que el recurso pertenece al usuario autenticado."""
    def dec(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            rid = kwargs.get(id_param)
            res = Model.query.filter_by(id=rid, user_id=current_user.id).first()
            if res is None:
                audit(f'idor_attempt_{Model.__tablename__}',
                      success=False, note=str(rid))
                return jsonify({'error': 'Not found'}), 404
            kwargs['resource'] = res
            return f(*args, **kwargs)
        return wrapped
    return dec


@lm.user_loader
def load_user(uid):
    return User.query.get(int(uid))


@app.after_request
def sec_headers(r):
    r.headers['X-Content-Type-Options'] = 'nosniff'
    r.headers['X-Frame-Options']        = 'DENY'
    r.headers['X-XSS-Protection']       = '1; mode=block'
    # CORS abierto solo para desarrollo local
    origin = request.headers.get('Origin', '')
    if 'localhost' in origin or '127.0.0.1' in origin:
        r.headers['Access-Control-Allow-Origin']  = origin
        r.headers['Access-Control-Allow-Credentials'] = 'true'
        r.headers['Access-Control-Allow-Headers'] = \
            'Content-Type, Authorization'
        r.headers['Access-Control-Allow-Methods'] = \
            'GET, POST, PUT, DELETE, OPTIONS'
    return r


@app.route('/api/<path:path>', methods=['OPTIONS'])
def options_handler(path):
    """Responde preflight CORS para todas las rutas /api/"""
    return '', 204

# ══════════════════════════════════════════════════════════════════════════════
# IRS 2025 TAX ENGINE
# ══════════════════════════════════════════════════════════════════════════════
BRACKETS_2025 = {
    'single':  [(11925,.10),(48475,.12),(103350,.22),(197300,.24),
                (250525,.32),(626350,.35),(float('inf'),.37)],
    'married': [(23850,.10),(96950,.12),(206700,.22),(394600,.24),
                (501050,.32),(751600,.35),(float('inf'),.37)],
    'hoh':     [(17000,.10),(64850,.12),(103350,.22),(197300,.24),
                (250500,.32),(626350,.35),(float('inf'),.37)],
}
STD_DED    = {'single': 15750, 'married': 31500, 'hoh': 23625}
STATE_RATES = {
    'Texas': 0, 'Florida': 0, 'Nevada': 0, 'Wyoming': 0,
    'California': .093, 'New York': .065,
    'Illinois': .0495, 'Arizona': .025, 'Colorado': .04,
}


def calc_taxes(gross, expenses, filing='single', state='Texas',
               children=0, sep_ira=0, senior=0):
    status  = filing if filing in BRACKETS_2025 else 'single'
    net     = max(0.0, gross - expenses - sep_ira)
    se_base = net * 0.9235
    se_tax  = se_base * 0.153
    se_ded  = se_tax * 0.5
    qbi     = net * 0.20
    std     = STD_DED.get(status, 15750)
    sen_d   = senior * 6000
    taxable = max(0.0, net - se_ded - qbi - std - sen_d)

    inc_tax, prev = 0.0, 0.0
    rem = taxable
    for limit, rate in BRACKETS_2025[status]:
        if rem <= 0:
            break
        slc      = min(rem, limit - prev)
        inc_tax += slc * rate
        rem     -= slc
        prev     = limit

    sr    = STATE_RATES.get(state, 0)
    st_tx = taxable * sr
    ctc   = min(children * 2200, max(0.0, inc_tax))
    total = max(0.0, se_tax + inc_tax + st_tx - ctc)
    eff   = round(total / gross * 100, 1) if gross > 0 else 0

    return dict(
        net_profit       = round(net, 2),
        se_tax           = round(se_tax, 2),
        se_deduction     = round(se_ded, 2),
        qbi_deduction    = round(qbi, 2),
        standard_deduction = std,
        taxable_income   = round(taxable, 2),
        income_tax       = round(inc_tax, 2),
        state_tax        = round(st_tx, 2),
        child_tax_credit = round(ctc, 2),
        total_tax        = round(total, 2),
        effective_rate   = eff,
        set_aside        = round(total / 4, 2),
    )

# ══════════════════════════════════════════════════════════════════════════════
# FRONTEND
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/')
def index():
    return send_file(os.path.join(BASE_DIR, 'templates', 'index.html'))

@app.route('/static/<path:path>')
def static_files(path):
    return send_from_directory(os.path.join(BASE_DIR, 'static'), path)

# ══════════════════════════════════════════════════════════════════════════════
# AUTH
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/api/register', methods=['POST'])
def register():
    d      = request.get_json(silent=True) or {}
    name   = d.get('name', '').strip()
    email  = d.get('email', '').strip().lower()
    pw     = d.get('password', '')
    state  = d.get('state', 'Texas')
    filing = d.get('filing_status', 'single')

    if not all([name, email, pw]):
        return jsonify({'error': 'All fields required'}), 400
    if len(pw) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email already registered'}), 409

    u = User(email=email, full_name=name, state=state, filing_status=filing)
    u.set_password(pw)
    db.session.add(u)
    db.session.commit()

    login_user(u, remember=False)
    flask_session.permanent = True
    audit('register')
    log.info(f'New user: {email}')
    return jsonify({'user': u.pub()}), 201


@app.route('/api/login', methods=['POST'])
def login():
    d     = request.get_json(silent=True) or {}
    email = d.get('email', '').strip().lower()
    pw    = d.get('password', '')

    if not email or not pw:
        return jsonify({'error': 'Email and password required'}), 400

    u     = User.query.filter_by(email=email).first()
    dummy = generate_password_hash('dummy_timing_protection')
    ok    = u is not None and u.check_password(pw)
    if not ok:
        check_password_hash(dummy, pw)   # timing-safe

    if not ok:
        audit('login_fail', success=False, note=email)
        return jsonify({'error': 'Invalid credentials'}), 401
    if not u.is_active:
        return jsonify({'error': 'Account suspended'}), 403

    u.last_login = datetime.utcnow()
    db.session.commit()
    login_user(u, remember=False)
    flask_session.permanent = True
    audit('login_ok')
    return jsonify({'user': u.pub()}), 200


@app.route('/api/logout', methods=['POST'])
def logout():
    audit('logout')
    logout_user()
    flask_session.clear()
    return jsonify({'ok': True})


@app.route('/api/me')
@login_required
def me():
    return jsonify(current_user.pub())

# ══════════════════════════════════════════════════════════════════════════════
# DASHBOARD
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/api/dashboard')
@login_required
def dashboard():
    uid  = current_user.id
    year = request.args.get('year', 2025, type=int)

    from sqlalchemy import func
    gross = float(db.session.query(
        func.coalesce(func.sum(Income.amount), 0)
    ).filter_by(user_id=uid, tax_year=year).scalar() or 0)

    exp = float(db.session.query(
        func.coalesce(
            func.sum(Receipt.amount * Receipt.deductible_pct / 100.0), 0)
    ).filter_by(user_id=uid, tax_year=year).scalar() or 0)

    rec_count = Receipt.query.filter_by(user_id=uid, tax_year=year).count()
    taxes     = calc_taxes(gross, exp, current_user.filing_status,
                           current_user.state)

    recent_inc = Income.query.filter_by(user_id=uid)\
                     .order_by(Income.created_at.desc()).limit(5).all()
    recent_rec = Receipt.query.filter_by(user_id=uid)\
                     .order_by(Receipt.created_at.desc()).limit(5).all()

    return jsonify({
        'summary': {
            'total_income':   gross,
            'total_expenses': exp,
            'receipt_count':  rec_count,
        },
        'taxes':           taxes,
        'recent_incomes':  [i.to_dict() for i in recent_inc],
        'recent_receipts': [r.to_dict() for r in recent_rec],
    })

# ══════════════════════════════════════════════════════════════════════════════
# INCOMES
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/api/incomes', methods=['GET'])
@login_required
def get_incomes():
    year  = request.args.get('year', 2025, type=int)
    items = Income.query.filter_by(user_id=current_user.id, tax_year=year)\
                  .order_by(Income.date.desc()).all()
    return jsonify([i.to_dict() for i in items])


@app.route('/api/incomes', methods=['POST'])
@login_required
def create_income():
    d = request.get_json(silent=True) or {}
    try:
        amt = float(d.get('amount', 0))
        assert amt > 0
    except Exception:
        return jsonify({'error': 'Invalid amount'}), 400

    inc = Income(
        user_id     = current_user.id,
        source      = str(d.get('source', '')).strip()[:255] or 'Unknown',
        amount      = amt,
        date        = d.get('date', datetime.utcnow().strftime('%Y-%m-%d')),
        invoice_num = str(d.get('invoice_num', '')).strip()[:100],
        tax_year    = int(d.get('tax_year', 2025)),
    )
    db.session.add(inc)
    db.session.commit()
    audit('income_create', note=str(inc.id))
    return jsonify(inc.to_dict()), 201


@app.route('/api/incomes/<int:item_id>', methods=['DELETE'])
@login_required
@owned(Income)
def delete_income(item_id, resource):
    db.session.delete(resource)
    db.session.commit()
    audit('income_delete', note=str(item_id))
    return jsonify({'ok': True})

# ══════════════════════════════════════════════════════════════════════════════
# RECEIPTS
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/api/receipts', methods=['GET'])
@login_required
def get_receipts():
    year  = request.args.get('year', 2025, type=int)
    items = Receipt.query.filter_by(user_id=current_user.id, tax_year=year)\
                   .order_by(Receipt.date.desc()).all()
    return jsonify([r.to_dict() for r in items])


@app.route('/api/receipts/<int:item_id>', methods=['GET'])
@login_required
@owned(Receipt)
def get_receipt(item_id, resource):
    return jsonify(resource.to_dict())


@app.route('/api/receipts/<int:item_id>', methods=['PUT'])
@login_required
@owned(Receipt)
def update_receipt(item_id, resource):
    d = request.get_json(silent=True) or {}
    for field in ('vendor', 'date', 'category', 'notes'):
        if field in d:
            setattr(resource, field, str(d[field]).strip()[:255])
    if 'amount' in d:
        try:
            v = float(d['amount'])
            assert v >= 0
            resource.amount = v
        except Exception:
            return jsonify({'error': 'Invalid amount'}), 400
    if 'deductible_pct' in d:
        v = int(d['deductible_pct'])
        if v not in (0, 50, 100):
            return jsonify({'error': 'deductible_pct must be 0, 50 or 100'}), 400
        resource.deductible_pct = v
    db.session.commit()
    audit('receipt_update', note=str(item_id))
    return jsonify(resource.to_dict())


@app.route('/api/receipts/<int:item_id>', methods=['DELETE'])
@login_required
@owned(Receipt)
def delete_receipt(item_id, resource):
    db.session.delete(resource)
    db.session.commit()
    audit('receipt_delete', note=str(item_id))
    return jsonify({'ok': True})

# ══════════════════════════════════════════════════════════════════════════════
# AI RECEIPT SCAN
# ══════════════════════════════════════════════════════════════════════════════
ALLOWED_EXT = {'jpg', 'jpeg', 'png', 'gif', 'webp', 'pdf'}


def allowed_file(fname):
    return '.' in fname and fname.rsplit('.', 1)[1].lower() in ALLOWED_EXT


def ai_scan_receipt(filepath, filename):
    api_key = os.environ.get('ANTHROPIC_API_KEY')
    if not api_key:
        log.warning('ANTHROPIC_API_KEY not set — using demo data')
        return _demo_receipt(filename)
    try:
        import anthropic, base64, mimetypes
        client = anthropic.Anthropic(api_key=api_key)
        ext  = filename.rsplit('.', 1)[-1].lower()
        mime = mimetypes.types_map.get(f'.{ext}', 'image/jpeg')
        with open(filepath, 'rb') as f:
            b64 = base64.b64encode(f.read()).decode()

        prompt = """Analyze this receipt/invoice and extract:
1. Vendor/business name
2. Total amount (number only)
3. Date (YYYY-MM-DD)
4. Category: Materials & Supplies | Tools & Equipment | Vehicle & Gas |
   Phone & Internet | Office Supplies | Meals — Business |
   Professional Services | Insurance | Advertising | Other
5. Deductibility: 100 (business), 50 (mixed), 0 (personal)
6. Brief notes

Respond ONLY with JSON (no markdown):
{"vendor":"","amount":0,"date":"","category":"","deductible_pct":100,"notes":"","confidence":0.95}"""

        msg = client.messages.create(
            model='claude-sonnet-4-20250514',
            max_tokens=300,
            messages=[{'role': 'user', 'content': [
                {'type': 'image', 'source': {
                    'type': 'base64', 'media_type': mime, 'data': b64}},
                {'type': 'text', 'text': prompt},
            ]}]
        )
        raw = msg.content[0].text.strip()
        if raw.startswith('```'):
            raw = raw.split('\n', 1)[1].rsplit('```', 1)[0]
        data = json.loads(raw)
        return {
            'vendor':         str(data.get('vendor', '')),
            'amount':         float(data.get('amount', 0)),
            'date':           str(data.get('date',
                                  datetime.utcnow().strftime('%Y-%m-%d'))),
            'category':       str(data.get('category', 'Other')),
            'deductible_pct': int(data.get('deductible_pct', 100)),
            'notes':          str(data.get('notes', '')),
            'confidence':     float(data.get('confidence', 0.90)),
        }
    except Exception as e:
        log.error(f'AI scan error: {e}')
        return _demo_receipt(filename)


def _demo_receipt(filename):
    demos = [
        {'vendor': 'Home Depot', 'amount': 487.32, 'date': '2025-05-27',
         'category': 'Materials & Supplies', 'deductible_pct': 100,
         'notes': 'Wire, conduit and electrical boxes', 'confidence': 0.97},
        {'vendor': 'Shell Gas Station', 'amount': 89.50, 'date': '2025-05-24',
         'category': 'Vehicle & Gas', 'deductible_pct': 100,
         'notes': 'Fuel for work vehicle', 'confidence': 0.95},
        {'vendor': 'AT&T', 'amount': 95.00, 'date': '2025-05-22',
         'category': 'Phone & Internet', 'deductible_pct': 50,
         'notes': 'Cell phone — 50% business use', 'confidence': 0.92},
        {'vendor': 'Ace Hardware', 'amount': 234.15, 'date': '2025-05-20',
         'category': 'Tools & Equipment', 'deductible_pct': 100,
         'notes': 'Drill bits and safety equipment', 'confidence': 0.96},
    ]
    import hashlib
    idx = int(hashlib.md5(filename.encode()).hexdigest(), 16) % len(demos)
    return demos[idx]


@app.route('/api/receipts/scan', methods=['POST'])
@login_required
@limiter.limit('20 per hour')
def scan_receipt():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    f = request.files['file']
    if not f.filename or not allowed_file(f.filename):
        return jsonify({'error': 'Invalid file type. Use JPG, PNG or PDF'}), 400

    fname = secure_filename(f.filename)
    ts    = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    saved = f'{current_user.id}_{ts}_{fname}'
    path  = os.path.join(app.config['UPLOAD_FOLDER'], saved)
    f.save(path)

    ai = ai_scan_receipt(path, fname)
    rec = Receipt(
        user_id        = current_user.id,
        vendor         = ai['vendor'],
        amount         = ai['amount'],
        date           = ai['date'],
        category       = ai['category'],
        deductible_pct = ai['deductible_pct'],
        notes          = ai['notes'],
        file_url       = f'/api/receipts/file/{saved}',
        ai_confidence  = ai['confidence'],
        ai_raw         = json.dumps(ai),
        tax_year       = 2025,
    )
    db.session.add(rec)
    db.session.commit()
    audit('receipt_scan', note=str(rec.id))
    return jsonify({'receipt': rec.to_dict(), 'ai_data': ai}), 201


@app.route('/api/receipts/file/<path:filename>')
@login_required
def serve_receipt_file(filename):
    if not filename.startswith(f'{current_user.id}_'):
        return jsonify({'error': 'Not found'}), 404
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# ══════════════════════════════════════════════════════════════════════════════
# TAX CALCULATOR
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/api/tax/calculate', methods=['POST'])
@login_required
def tax_calculate():
    d = request.get_json(silent=True) or {}
    result = calc_taxes(
        gross    = float(d.get('gross_income', 0)),
        expenses = float(d.get('expenses', 0)),
        filing   = d.get('filing_status', current_user.filing_status),
        state    = d.get('state', current_user.state),
        children = int(d.get('children', 0)),
        sep_ira  = float(d.get('sep_ira', 0)),
        senior   = int(d.get('senior', 0)),
    )
    return jsonify(result)

# ══════════════════════════════════════════════════════════════════════════════
# REPORTS
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/api/reports/summary')
@login_required
def report_summary():
    uid  = current_user.id
    year = request.args.get('year', 2025, type=int)

    from sqlalchemy import func
    gross = float(db.session.query(
        func.coalesce(func.sum(Income.amount), 0)
    ).filter_by(user_id=uid, tax_year=year).scalar() or 0)

    exp = float(db.session.query(
        func.coalesce(
            func.sum(Receipt.amount * Receipt.deductible_pct / 100.0), 0)
    ).filter_by(user_id=uid, tax_year=year).scalar() or 0)

    cat_q = db.session.query(
        Receipt.category,
        func.sum(Receipt.amount * Receipt.deductible_pct / 100.0)
    ).filter_by(user_id=uid, tax_year=year)\
     .group_by(Receipt.category).all()

    taxes = calc_taxes(gross, exp, current_user.filing_status,
                       current_user.state)

    return jsonify({
        'year':             year,
        'gross_income':     gross,
        'total_deductions': exp,
        'by_category':      {c: round(float(v), 2) for c, v in cat_q},
        'taxes':            taxes,
        'schedule_c': {
            'line_1_gross':       gross,
            'line_28_expenses':   exp,
            'line_31_net_profit': taxes['net_profit'],
        },
    })

# ══════════════════════════════════════════════════════════════════════════════
# ADMIN
# ══════════════════════════════════════════════════════════════════════════════
def require_role(*roles):
    def dec(f):
        @wraps(f)
        @login_required
        def wrapped(*a, **kw):
            if current_user.role not in roles:
                audit('unauthorized', success=False)
                return jsonify({'error': 'Forbidden'}), 403
            return f(*a, **kw)
        return wrapped
    return dec


@app.route('/api/admin/users')
@require_role('admin', 'superadmin')
def admin_users():
    audit('admin_list_users')
    return jsonify([u.pub() for u in
                    User.query.order_by(User.created_at.desc()).all()])


@app.route('/api/admin/stats')
@require_role('admin', 'superadmin')
def admin_stats():
    return jsonify({
        'total_users':    User.query.count(),
        'total_incomes':  Income.query.count(),
        'total_receipts': Receipt.query.count(),
        'audit_entries':  AuditLog.query.count(),
    })


@app.route('/api/admin/audit')
@require_role('superadmin')
def admin_audit():
    page = request.args.get('page', 1, type=int)
    logs = AuditLog.query.order_by(AuditLog.ts.desc())\
                   .paginate(page=page, per_page=50, error_out=False)
    return jsonify({
        'total': logs.total,
        'logs':  [{'id': l.id, 'user_id': l.user_id, 'action': l.action,
                   'ip': l.ip, 'success': l.success,
                   'ts': l.ts.isoformat()} for l in logs.items],
    })

# ══════════════════════════════════════════════════════════════════════════════
# ERROR HANDLERS
# ══════════════════════════════════════════════════════════════════════════════
@app.errorhandler(429)
def too_many(e):
    return jsonify(
        {'error': 'Too many attempts. Please wait before trying again.'}), 429

@app.errorhandler(413)
def too_large(e):
    return jsonify({'error': 'File too large. Maximum 16 MB.'}), 413

@app.errorhandler(404)
def not_found(e):
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Not found'}), 404
    return send_file(os.path.join(BASE_DIR, 'templates', 'index.html'))

@app.errorhandler(500)
def server_err(e):
    log.error(f'500: {e}')
    return jsonify({'error': 'Internal server error'}), 500

# ══════════════════════════════════════════════════════════════════════════════
# DEMO DATA
# ══════════════════════════════════════════════════════════════════════════════
def create_demo_data():
    demo_email = 'demo@findxpert.com'
    if User.query.filter_by(email=demo_email).first():
        return  # ya existe

    u = User(email=demo_email, full_name='Demo User',
             state='Texas', filing_status='single', role='user')
    u.set_password('Demo1234!')
    admin = User(email='admin@findxpert.com', full_name='FindXpert Admin',
                 state='Texas', filing_status='single', role='superadmin')
    admin.set_password('Admin1234!')
    db.session.add_all([u, admin])
    db.session.flush()

    incomes = [
        Income(user_id=u.id, source='Johnson Residence — Electrical Work',
               amount=3200, date='2025-05-28', invoice_num='INV-0041', tax_year=2025),
        Income(user_id=u.id, source='Martinez Office — Panel Upgrade',
               amount=2800, date='2025-05-25', invoice_num='INV-0040', tax_year=2025),
        Income(user_id=u.id, source='Williams Home — Full Rewiring',
               amount=4100, date='2025-05-18', invoice_num='INV-0039', tax_year=2025),
        Income(user_id=u.id, source='Thompson Commercial — EV Charger',
               amount=1140, date='2025-05-10', invoice_num='INV-0038', tax_year=2025),
    ]
    receipts = [
        Receipt(user_id=u.id, vendor='Home Depot', amount=487.32,
                date='2025-05-27', category='Materials & Supplies',
                deductible_pct=100, notes='Wire and conduit for Johnson job',
                tax_year=2025, ai_confidence=0.97),
        Receipt(user_id=u.id, vendor='Shell Gas Station', amount=89.50,
                date='2025-05-24', category='Vehicle & Gas',
                deductible_pct=100, notes='142 miles × $0.70 IRS 2025 rate',
                tax_year=2025, ai_confidence=0.95),
        Receipt(user_id=u.id, vendor='AT&T', amount=95.00,
                date='2025-05-22', category='Phone & Internet',
                deductible_pct=50, notes='Cell phone — 50% business use',
                tax_year=2025, ai_confidence=0.92),
        Receipt(user_id=u.id, vendor='Ace Hardware', amount=234.15,
                date='2025-05-20', category='Tools & Equipment',
                deductible_pct=100, notes='Drill bits and safety equipment',
                tax_year=2025, ai_confidence=0.96),
        Receipt(user_id=u.id, vendor="McDonald's", amount=14.50,
                date='2025-05-21', category='Meals — Business',
                deductible_pct=0, notes='Personal lunch — not deductible',
                tax_year=2025, ai_confidence=0.99),
    ]
    db.session.add_all(incomes + receipts)
    db.session.commit()
    log.info('✅ Demo data created')


with app.app_context():
    db.create_all()
    create_demo_data()
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# ══════════════════════════════════════════════════════════════════════════════
# MAIN — Puerto 5050 para evitar conflicto con AirPlay en macOS
# ══════════════════════════════════════════════════════════════════════════════
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5050))
    log.info(f'')
    log.info(f'  ╔══════════════════════════════════════╗')
    log.info(f'  ║   FindXpert v2.1 — Xpert Labs LLC   ║')
    log.info(f'  ╠══════════════════════════════════════╣')
    log.info(f'  ║  URL:   http://localhost:{port}        ║')
    log.info(f'  ║  Demo:  demo@findxpert.com            ║')
    log.info(f'  ║  Pass:  Demo1234!                     ║')
    log.info(f'  ║  Admin: admin@findxpert.com           ║')
    log.info(f'  ║  Ctrl+C para detener                  ║')
    log.info(f'  ╚══════════════════════════════════════╝')
    log.info(f'')
    is_dev = os.environ.get('FLASK_ENV','development') == 'development'
    app.run(host='0.0.0.0', port=port, debug=is_dev)
