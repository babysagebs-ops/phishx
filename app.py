# app.py
import json
import warnings
import pickle
import numpy as np
import requests
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv
load_dotenv()
from flask import (Flask, request, render_template, redirect,
                   url_for, flash, abort, make_response)
from flask_login import (LoginManager, login_user, logout_user,
                         login_required, current_user)
from flask_bcrypt import Bcrypt
from functools import wraps
from sqlalchemy import create_engine, text
from sqlalchemy.exc import OperationalError

warnings.filterwarnings('ignore')

from models import db, User, Scan, Report, Tip
from feature import FeatureExtraction

# ─────────────────────────────────────────────
# APP SETUP
# ─────────────────────────────────────────────
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'fallback-dev-key')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# Supabase (new) — copy connection string from Supabase dashboard
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///phishx.db')

# Allow local fallback when remote DB is not reachable.
# This prevents startup failure due to an unreachable Supabase/Postgres host.
try:
    test_engine = create_engine(app.config['SQLALCHEMY_DATABASE_URI'])
    with test_engine.connect() as conn:
        conn.execute(text('SELECT 1'))
    db.init_app(app)
except OperationalError:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///phishx.db'
    db.init_app(app)
    print('Warning: remote database unreachable, falling back to sqlite:///phishx.db')

bcrypt       = Bcrypt(app)
login_manager = LoginManager(app)
from flask_login import AnonymousUserMixin

class AnonymousUser(AnonymousUserMixin):
    def is_admin(self):
        return False

login_manager.anonymous_user = AnonymousUser
login_manager.login_view       = 'login'
login_manager.login_message    = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

# Load ML model
with open('pickle/model.pkl', 'rb') as f:
    gbc = pickle.load(f)

FEATURE_NAMES = [
    "UsingIp", "LongUrl", "ShortUrl", "Symbol", "Redirecting",
    "PrefixSuffix", "SubDomains", "HTTPS", "DomainRegLen", "Favicon",
    "NonStdPort", "HTTPSDomainURL", "RequestURL", "AnchorURL",
    "LinksInScriptTags", "ServerFormHandler", "InfoEmail", "AbnormalURL",
    "WebsiteForwarding", "StatusBarCust", "DisableRightClick",
    "UsingPopupWindow", "IframeRedirection", "AgeofDomain", "DNSRecording",
    "WebsiteTraffic", "PageRank", "GoogleIndex", "LinksPointingToPage",
    "StatsReport"
]

# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def admin_required(f):
    """Decorator — blocks non-admin users."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin():
            abort(403)
        return f(*args, **kwargs)
    return decorated


# ─────────────────────────────────────────────
# AUTH ROUTES
# ─────────────────────────────────────────────


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username  = request.form.get('username', '').strip()
        email     = request.form.get('email', '').strip().lower()
        password  = request.form.get('password', '')
        password2 = request.form.get('password2', '')

        # Basic validation
        error = None
        if not username or not email or not password:
            error = 'All fields are required.'
        elif password != password2:
            error = 'Passwords do not match.'
        elif len(password) < 6:
            error = 'Password must be at least 6 characters.'
        elif User.query.filter_by(email=email).first():
            error = 'An account with that email already exists.'
        elif User.query.filter_by(username=username).first():
            error = 'That username is already taken.'

        if error:
            flash(error, 'error')
            return render_template('signup.html')

        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username=username, email=email, password=hashed_pw)
        db.session.add(user)
        db.session.commit()

        flash('Account created! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        email    = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        remember = request.form.get('remember') == 'on'

        user = User.query.filter_by(email=email).first()

        if not user or not bcrypt.check_password_hash(user.password, password):
            flash('Invalid email or password.', 'error')
            return render_template('login.html')

        login_user(user, remember=remember)
        next_page = request.args.get('next')
        return redirect(next_page or url_for('index'))

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))


# ─────────────────────────────────────────────
# MAIN SCANNER
# ─────────────────────────────────────────────
MAX_GUEST_TRIALS = 2

@app.route('/', methods=['GET', 'POST'])
def index():
    # ── Guest trial management ──────────────────
    if not current_user.is_authenticated:
        trials_used = int(request.cookies.get('guest_trials', 0))

        if request.method == 'POST':
            # Trial limit hit — redirect to signup
            if trials_used >= MAX_GUEST_TRIALS:
                flash('You have used your 2 free scans. Sign up to continue.', 'info')
                return redirect(url_for('signup'))

            url        = request.form.get('url', '').strip()
            if not url:
                flash('Please enter a URL.', 'error')
                resp = render_template('index.html', xx=-1,
                                       is_guest=True,
                                       trials_used=trials_used,
                                       trials_left=MAX_GUEST_TRIALS - trials_used)
                return resp

            # Feature extraction
            obj      = FeatureExtraction(url)
            features = obj.getFeaturesList()
            x        = np.array(features).reshape(1, 30)

            safe_prob   = float(gbc.predict_proba(x)[0, 1])
            risk_score  = round((1 - safe_prob) * 100)
            is_phishing = safe_prob < 0.5
            feature_dict = dict(zip(FEATURE_NAMES, features))

            # Guest scans are NOT saved to DB
            new_trials = trials_used + 1
            trials_left = MAX_GUEST_TRIALS - new_trials

            resp = make_response(render_template(
                'index.html',
                xx           = round(safe_prob, 2),
                url          = url,
                risk_score   = risk_score,
                is_phishing  = is_phishing,
                share_token  = None,      # guests don't get shareable links
                feature_dict = feature_dict,
                is_guest     = True,
                trials_used  = new_trials,
                trials_left  = trials_left,
                show_signup_prompt = (new_trials >= MAX_GUEST_TRIALS),
            ))
            # Store trial count in cookie (expires in 1 day)
            resp.set_cookie('guest_trials', str(new_trials),
                            max_age=86400, httponly=True, samesite='Lax')
            return resp

        # GET — just show scanner with trial info
        trials_left = MAX_GUEST_TRIALS - trials_used
        if trials_used >= MAX_GUEST_TRIALS:
            # Already used all trials — send straight to signup
            flash('You have used your 2 free scans. Sign up to continue scanning.', 'info')
            return redirect(url_for('signup'))

        return render_template('index.html', xx=-1,
                               is_guest=True,
                               trials_used=trials_used,
                               trials_left=trials_left)

    # ── Authenticated user ──────────────────────
    if request.method == 'POST':
        url        = request.form.get('url', '').strip()
        is_private = request.form.get('private') == 'on'

        if not url:
            flash('Please enter a URL.', 'error')
            return render_template('index.html', xx=-1, is_guest=False)

        obj      = FeatureExtraction(url)
        features = obj.getFeaturesList()
        x        = np.array(features).reshape(1, 30)

        safe_prob   = float(gbc.predict_proba(x)[0, 1])
        risk_score  = round((1 - safe_prob) * 100)
        is_phishing = safe_prob < 0.5
        feature_dict = dict(zip(FEATURE_NAMES, features))

        scan = Scan(
            user_id       = current_user.id,
            url           = url,
            risk_score    = risk_score,
            is_phishing   = is_phishing,
            safe_prob     = round(safe_prob, 4),
            features_json = json.dumps(feature_dict),
            is_private    = is_private,
        )
        db.session.add(scan)
        db.session.commit()

        return render_template(
            'index.html',
            xx           = round(safe_prob, 2),
            url          = url,
            risk_score   = risk_score,
            is_phishing  = is_phishing,
            share_token  = scan.share_token,
            feature_dict = feature_dict,
            is_guest     = False,
        )

    return render_template('index.html', xx=-1, is_guest=False)


# ─────────────────────────────────────────────
# SHARED RESULT PAGE
# ─────────────────────────────────────────────
@app.route('/result/<token>')
def shared_result(token):
    scan = Scan.query.filter_by(share_token=token).first_or_404()

    if scan.is_private:
        abort(403)

    feature_dict = json.loads(scan.features_json) if scan.features_json else {}

    return render_template(
        'shared_result.html',
        scan         = scan,
        xx           = scan.safe_prob,
        url          = scan.url,
        risk_score   = scan.risk_score,
        is_phishing  = scan.is_phishing,
        feature_dict = feature_dict,
        share_token  = scan.share_token,
    )


# ─────────────────────────────────────────────
# REPORT A URL
# ─────────────────────────────────────────────
@app.route('/report/<token>', methods=['POST'])
def report_url(token):
    scan   = Scan.query.filter_by(share_token=token).first_or_404()
    reason = request.form.get('reason', 'other')
    note   = request.form.get('note', '').strip()

    report = Report(
        scan_id = scan.id,
        user_id = current_user.id if current_user.is_authenticated else None,
        reason  = reason,
        note    = note,
    )
    db.session.add(report)
    db.session.commit()

    flash('Thank you — your report has been submitted for review.', 'success')
    return redirect(url_for('shared_result', token=token))


# ─────────────────────────────────────────────
# USER SCAN HISTORY
# ─────────────────────────────────────────────
@app.route('/history')
@login_required
def history():
    scans = (Scan.query
             .filter_by(user_id=current_user.id)
             .order_by(Scan.scanned_at.desc())
             .all())
    return render_template('history.html', scans=scans)


@app.route('/api/recent-scans')
@login_required
def api_recent_scans():
    """Returns the current user's most recent scans as JSON.
    Used by the homepage 'Recent Scans' panel so it reflects the
    database instead of browser localStorage."""
    scans = (Scan.query
             .filter_by(user_id=current_user.id)
             .order_by(Scan.scanned_at.desc())
             .limit(10)
             .all())
    return {
        'scans': [
            {
                'url': s.url,
                'score': s.safe_prob,
                'label': 'Safe' if s.safe_prob >= 0.5 else ('Suspicious' if s.safe_prob >= 0.3 else 'Malicious'),
                'ts': s.scanned_at.isoformat(),
                'share_token': s.share_token if not s.is_private else None,
            }
            for s in scans
        ]
    }


# ─────────────────────────────────────────────
# NOTIFICATIONS API
# ─────────────────────────────────────────────
@app.route('/api/notifications')
@login_required
def api_notifications():
    """Returns unread notification counts for the current user.
    Used by the bell icon to show live badge counts."""
    notes = []

    if current_user.is_admin():
        pending = Report.query.filter_by(status='pending').count()
        if pending:
            notes.append({
                'type':    'report',
                'message': f'{pending} URL report{"s" if pending > 1 else ""} awaiting review',
                'link':    url_for('admin_dashboard'),
                'icon':    'fa-flag',
            })
        # Scans in last hour
        from datetime import timedelta
        recent_count = Scan.query.filter(
            Scan.scanned_at >= datetime.utcnow() - timedelta(hours=1)
        ).count()
        if recent_count:
            notes.append({
                'type':    'scan',
                'message': f'{recent_count} scan{"s" if recent_count > 1 else ""} in the last hour',
                'link':    url_for('admin_dashboard'),
                'icon':    'fa-magnifying-glass',
            })
    else:
        # Regular user — notify about their own recent scans
        user_scans = Scan.query.filter_by(user_id=current_user.id).count()
        if user_scans:
            notes.append({
                'type':    'history',
                'message': f'You have {user_scans} saved scan{"s" if user_scans > 1 else ""} in your history',
                'link':    url_for('history'),
                'icon':    'fa-clock-rotate-left',
            })

    return {'notifications': notes, 'count': len(notes)}


# ─────────────────────────────────────────────
# LIVE SECURITY NEWS (fetched server-side)
#
# We used to hit rss2json.com directly from the browser, but that free
# tier now requires an API key (returns HTTP 422 without one), and the
# CORS-proxy fallback (allorigins.win) doesn't send CORS headers reliably
# either. Fetching the RSS feeds ourselves, server-side, sidesteps both
# problems entirely — the browser only ever talks to our own API.
# ─────────────────────────────────────────────
NEWS_FEEDS = [
    {'name': 'The Hacker News',   'url': 'https://feeds.feedburner.com/TheHackersNews', 'color': '#e74c3c'},
    {'name': 'BleepingComputer',  'url': 'https://www.bleepingcomputer.com/feed/',       'color': '#2980b9'},
    {'name': 'Krebs on Security', 'url': 'https://krebsonsecurity.com/feed/',            'color': '#27ae60'},
    {'name': 'SecurityWeek',      'url': 'https://www.securityweek.com/feed',            'color': '#8e44ad'},
]

_news_cache = {'articles': [], 'fetched_at': None}
NEWS_CACHE_TTL = timedelta(minutes=15)


def _parse_rss(xml_text, feed):
    """Turns a raw RSS <item> list into the shape the frontend expects."""
    articles = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return articles

    for item in root.findall('.//item'):
        def text_of(tag):
            el = item.find(tag)
            return el.text.strip() if el is not None and el.text else ''
        articles.append({
            'title':       text_of('title'),
            'link':        text_of('link'),
            'description': text_of('description'),
            'pubDate':     text_of('pubDate'),
            'source':      feed['name'],
            'color':       feed['color'],
        })
    return articles


@app.route('/api/news')
def api_news():
    """Fetches security-news RSS feeds server-side (no CORS, no third-party
    JSON-proxy quota) and returns them combined as JSON. Cached in memory
    for NEWS_CACHE_TTL so a burst of page loads doesn't hammer the feeds."""
    now = datetime.utcnow()
    if _news_cache['fetched_at'] and now - _news_cache['fetched_at'] < NEWS_CACHE_TTL:
        return {'articles': _news_cache['articles'], 'cached': True}

    all_articles = []
    failed = []
    headers = {'User-Agent': 'Mozilla/5.0 (compatible; PhishXNewsBot/1.0)'}

    for feed in NEWS_FEEDS:
        try:
            resp = requests.get(feed['url'], headers=headers, timeout=6)
            resp.raise_for_status()
            all_articles.extend(_parse_rss(resp.text, feed))
        except Exception as e:
            failed.append(feed['name'])
            app.logger.warning(f"News feed failed: {feed['name']} — {e}")

    all_articles.sort(key=lambda a: a['pubDate'], reverse=True)

    # Only cache if we actually got something — don't lock in an empty result.
    if all_articles:
        _news_cache['articles']   = all_articles
        _news_cache['fetched_at'] = now

    return {'articles': all_articles, 'failed': failed}


@app.route('/tips')
def tips():
    # Group tips by category, ordered within each group
    all_tips = Tip.query.order_by(Tip.category, Tip.order, Tip.created_at).all()
    grouped  = {}
    for tip in all_tips:
        grouped.setdefault(tip.category, []).append(tip)
    return render_template('tips.html', grouped=grouped)


# ─────────────────────────────────────────────
# ADMIN — TIP MANAGEMENT
# ─────────────────────────────────────────────
@app.route('/admin/tips')
@login_required
@admin_required
def admin_tips():
    tips = Tip.query.order_by(Tip.category, Tip.order, Tip.created_at).all()
    return render_template('admin_tips.html', tips=tips)


@app.route('/admin/tips/add', methods=['POST'])
@login_required
@admin_required
def admin_tip_add():
    category = request.form.get('category', '').strip()
    title    = request.form.get('title', '').strip()
    body     = request.form.get('body', '').strip()
    icon     = request.form.get('icon', 'fa-shield-halved').strip()
    order    = int(request.form.get('order', 0) or 0)

    if not category or not title or not body:
        flash('Category, title and body are all required.', 'error')
        return redirect(url_for('admin_tips'))

    tip = Tip(
        category   = category,
        title      = title,
        body       = body,
        icon       = icon,
        order      = order,
        created_by = current_user.id,
    )
    db.session.add(tip)
    db.session.commit()
    flash(f'Tip "{title}" added successfully.', 'success')
    return redirect(url_for('admin_tips'))


@app.route('/admin/tips/<int:tip_id>/delete', methods=['POST'])
@login_required
@admin_required
def admin_tip_delete(tip_id):
    tip = Tip.query.get_or_404(tip_id)
    db.session.delete(tip)
    db.session.commit()
    flash('Tip deleted.', 'success')
    return redirect(url_for('admin_tips'))


# ─────────────────────────────────────────────
# ADMIN PANEL
# ─────────────────────────────────────────────
@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    total_users    = User.query.count()
    total_scans    = Scan.query.count()
    flagged_scans  = Scan.query.filter_by(is_phishing=True).count()
    pending_reports = Report.query.filter_by(status='pending').count()

    recent_scans   = (Scan.query
                      .order_by(Scan.scanned_at.desc())
                      .limit(10).all())
    recent_reports = (Report.query
                      .order_by(Report.reported_at.desc())
                      .limit(10).all())
    users          = User.query.order_by(User.created_at.desc()).all()

    return render_template(
        'admin.html',
        total_users     = total_users,
        total_scans     = total_scans,
        flagged_scans   = flagged_scans,
        pending_reports = pending_reports,
        recent_scans    = recent_scans,
        recent_reports  = recent_reports,
        users           = users,
    )


@app.route('/admin/reports/<int:report_id>/resolve', methods=['POST'])
@login_required
@admin_required
def resolve_report(report_id):
    report = Report.query.get_or_404(report_id)
    report.status = 'resolved'
    db.session.commit()
    flash(f'Report #{report_id} marked as resolved.', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/users/<int:user_id>/make-admin', methods=['POST'])
@login_required
@admin_required
def make_admin(user_id):
    user = User.query.get_or_404(user_id)
    user.role = 'admin'
    db.session.commit()
    flash(f'{user.username} is now an admin.', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/scans/<int:scan_id>/delete', methods=['POST'])
@login_required
@admin_required
def admin_delete_scan(scan_id):
    """Delete a single scan record and its associated reports."""
    scan = Scan.query.get_or_404(scan_id)
    # Delete child reports first to avoid FK constraint errors
    Report.query.filter_by(scan_id=scan.id).delete()
    db.session.delete(scan)
    db.session.commit()
    flash(f'Scan #{scan_id} deleted.', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/users/<int:user_id>/clear-history', methods=['POST'])
@login_required
@admin_required
def admin_clear_user_history(user_id):
    """Delete ALL scan records for a specific user."""
    user = User.query.get_or_404(user_id)
    scans = Scan.query.filter_by(user_id=user.id).all()
    for scan in scans:
        Report.query.filter_by(scan_id=scan.id).delete()
        db.session.delete(scan)
    db.session.commit()
    flash(f"All scan history for '{user.username}' has been deleted ({len(scans)} scans).", 'success')
    return redirect(url_for('admin_dashboard'))


# ─────────────────────────────────────────────
# ERROR PAGES
# ─────────────────────────────────────────────
@app.errorhandler(403)
def forbidden(e):
    return render_template('errors/403.html'), 403

@app.errorhandler(404)
def not_found(e):
    return render_template('errors/404.html'), 404


# ─────────────────────────────────────────────
# INIT DB + RUN
# ─────────────────────────────────────────────
if __name__ == '__main__':
    with app.app_context():
        db.create_all()

        # Default admin account
        if not User.query.filter_by(role='admin').first():
            admin_pw = bcrypt.generate_password_hash('admin123').decode('utf-8')
            admin    = User(username='admin', email='admin@phishx.com',
                            password=admin_pw, role='admin')
            db.session.add(admin)
            db.session.commit()
            print('Default admin created — email: admin@phishx.com  password: admin123')

        # Seed starter tips if none exist
        if Tip.query.count() == 0:
            seed = [
                ('URL Warning Signs', 'Check for IP addresses in URLs',
                 'Legitimate websites use domain names, not raw IP addresses like http://192.168.1.1/login. An IP address in a URL is a strong phishing indicator.',
                 'fa-network-wired', 1),
                ('URL Warning Signs', 'Watch for misspelled domains',
                 'Phishers register domains that look almost identical to real ones — paypa1.com, arnazon.com, g00gle.com. Always read the domain name character by character.',
                 'fa-magnifying-glass', 2),
                ('URL Warning Signs', 'Be cautious of very long URLs',
                 'Phishing URLs are often very long to hide the real domain or disguise redirect chains. If a URL looks unusually long or has many parameters, treat it with suspicion.',
                 'fa-ruler-horizontal', 3),
                ('URL Warning Signs', 'Look out for the @ symbol',
                 'The @ symbol in a URL causes browsers to ignore everything before it. http://paypal.com@evil.com actually takes you to evil.com, not PayPal.',
                 'fa-at', 4),
                ('Email Safety', 'Never click links in unexpected emails',
                 'If you receive an email asking you to verify your account, reset a password, or take urgent action, navigate directly to the website by typing the address yourself rather than clicking any link.',
                 'fa-envelope-circle-check', 1),
                ('Email Safety', 'Check the sender address carefully',
                 'Phishing emails often use addresses that look legitimate at a glance — support@paypa1.com or noreply@amazon-secure.net. Check the full email address, not just the display name.',
                 'fa-user-check', 2),
                ('Email Safety', 'Urgency is a red flag',
                 'Messages that create a sense of urgency — "Your account will be suspended in 24 hours" — are designed to make you act before you think. Legitimate organisations do not pressure you this way.',
                 'fa-clock', 3),
                ('Safe Browsing', 'Look for HTTPS but do not rely on it alone',
                 'HTTPS means your connection is encrypted, but it does not guarantee the site is legitimate. Many phishing sites now use HTTPS. Always check the domain name itself.',
                 'fa-lock', 1),
                ('Safe Browsing', 'Use a password manager',
                 'Password managers automatically fill credentials only on the real domain. If a site is a fake, your password manager will not recognise it and will not fill in your details — a built-in phishing defence.',
                 'fa-key', 2),
                ('Safe Browsing', 'Enable two-factor authentication',
                 'Even if a phisher steals your password, two-factor authentication means they cannot access your account without also having access to your phone or authenticator app.',
                 'fa-mobile-screen', 3),
                ('If You Get Caught', 'Change your password immediately',
                 'If you think you have entered your credentials on a phishing site, change your password on the real site immediately. If you reuse that password elsewhere, change it on those sites too.',
                 'fa-rotate', 1),
                ('If You Get Caught', 'Report the phishing site',
                 'Report phishing URLs to Google Safe Browsing (safebrowsing.google.com/safebrowsing/report_phish), PhishTank, and your country\'s national cyber security centre to help protect others.',
                 'fa-flag', 2),
            ]
            for cat, title, body, icon, order in seed:
                db.session.add(Tip(category=cat, title=title, body=body, icon=icon, order=order))
            db.session.commit()
            print(f'Seeded {len(seed)} starter tips.')

    app.run(debug=True)
