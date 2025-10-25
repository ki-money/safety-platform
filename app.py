from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import os
import mimetypes
import bleach
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash
from functools import wraps
from database import *
from ai_analytics import *
from translations import get_translation, get_all_translations, get_available_languages
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get('SESSION_SECRET') or os.environ.get('SECRET_KEY') or os.urandom(24)

app.config.update(
    UPLOAD_FOLDER='Uploads',
    ALLOWED_EXTENSIONS={'jpg', 'jpeg', 'png', 'mp4', 'mov'},
    ALLOWED_MIME_TYPES={'image/jpeg', 'image/png', 'video/mp4', 'video/quicktime'},
    MAX_CONTENT_LENGTH=10 * 1024 * 1024,
    SESSION_COOKIE_SECURE=os.environ.get('FLASK_ENV') == 'production',
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=3600
)

for folder in [app.config['UPLOAD_FOLDER'], 'templates', 'static', 'logs']:
    os.makedirs(folder, exist_ok=True)

# Initialize database
try:
    init_db()
    logger.info("Database initialized")
except Exception as e:
    logger.error(f"Database initialization failed: {str(e)}")


def get_user_language():
    """Get the current user's language preference."""
    if 'language' in session:
        return session['language']
    if 'lang' in request.args:
        lang = request.args.get('lang')
        if lang in get_available_languages():
            session['language'] = lang
            return lang
    session['language'] = 'English'
    return 'English'


@app.route('/set_language/<lang>')
def set_language(lang):
    """Set the user's language preference."""
    if lang in get_available_languages():
        session['language'] = lang
    return redirect(request.referrer or url_for('home'))


def login_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if role == 'police':
                if not session.get('police_logged_in') or not session.get('station'):
                    return redirect(url_for('police_login'))
            elif role == 'admin' and not session.get('admin_logged_in'):
                return redirect(url_for('admin_login'))
            return f(*args, **kwargs)

        return decorated_function

    return decorator


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS'] and \
        mimetypes.guess_type(filename)[0] in app.config['ALLOWED_MIME_TYPES']


def get_client_ip():
    return request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0]


def sanitize_input(data, max_length=1000):
    return bleach.clean(str(data)[:max_length]).strip() if data else ''


@app.route('/')
def home():
    try:
        lang = get_user_language()
        return render_template('index.html',
                               constituencies=get_all_constituencies(),
                               stats=get_system_statistics(),
                               lang=lang,
                               t=get_all_translations(lang),
                               available_languages=get_available_languages())
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        return render_template('error.html', message="Failed to load page", code=500), 500


@app.route('/report', methods=['GET', 'POST'])
def report():
    lang = get_user_language()

    if request.method == 'GET':
        return render_template('report_form.html',
                               constituencies=get_all_constituencies(),
                               settings=get_system_settings(),
                               lang=lang,
                               t=get_all_translations(lang),
                               available_languages=get_available_languages())

    try:
        category = sanitize_input(request.form.get('category', ''), 100)
        description = sanitize_input(request.form.get('description', ''), 2000)
        manual_location = sanitize_input(request.form.get('manual_location', ''), 200)
        constituency = sanitize_input(request.form.get('constituency', ''), 100)
        language = sanitize_input(request.form.get('language', 'English'), 50)

        try:
            lat = float(request.form.get('lat', -0.3031))
            lon = float(request.form.get('lon', 36.0800))
            if not (-5 <= lat <= 5 and 33 <= lon <= 42):
                lat, lon = -0.3031, 36.0800
        except:
            lat, lon = -0.3031, 36.0800

        if not all([category, description, manual_location, constituency]):
            return jsonify({'error': get_translation(lang, 'all_fields_required')}), 400

        if constituency not in [c[0] for c in get_all_constituencies()]:
            return jsonify({'error': 'Invalid constituency'}), 400

        media_path = None
        if 'media' in request.files:
            file = request.files['media']
            if file and file.filename and allowed_file(file.filename):
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = secure_filename(f"{timestamp}_{file.filename}")
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                media_path = filename

        spam_result = detect_spam({
            'description': description,
            'category': category,
            'manual_location': manual_location,
            'lat': lat,
            'lon': lon,
            'language': language
        })

        settings = get_system_settings()
        if spam_result['spam_score'] >= settings.get('auto_reject_threshold', 85):
            if media_path:
                try:
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], media_path))
                except:
                    pass
            return jsonify({'error': 'Report rejected'}), 400

        report_id = add_report(category, description, manual_location, lat, lon, constituency, language, media_path,
                               spam_result)
        add_audit_log('citizen', 'anonymous', f'Submitted report #{report_id}', f'Spam: {spam_result["spam_score"]}',
                      get_client_ip())

        # Return the report ID as a shorter, user-friendly format
        short_report_id = str(report_id)[-8:]  # Last 8 characters of MongoDB ObjectId

        return jsonify({
            'success': True,
            'report_id': short_report_id,
            'message': f'{get_translation(lang, "report_submitted")} Your Report ID: {short_report_id}'
        })

    except Exception as e:
        logger.error(f"Error: {str(e)}")
        return jsonify({'error': get_translation(lang, 'report_failed')}), 500


@app.route('/police/login', methods=['GET', 'POST'])
def police_login():
    lang = get_user_language()

    if request.method == 'POST':
        try:
            username = sanitize_input(request.form.get('username', ''), 100)
            password = request.form.get('password', '')

            if not username or not password:
                return render_template('police_login.html',
                                       error=get_translation(lang, 'all_fields_required'),
                                       lang=lang,
                                       t=get_all_translations(lang),
                                       available_languages=get_available_languages())

            credentials = verify_police_credentials(username, password)
            if credentials:
                session.permanent = True
                session['police_logged_in'] = True
                session['station'] = credentials['constituency']
                session['preferred_language'] = credentials['preferred_language']
                session['language'] = credentials['preferred_language']
                session['username'] = username
                add_audit_log('police', username, 'Logged in', None, get_client_ip())
                return redirect(url_for('police_dashboard'))

            return render_template('police_login.html',
                                   error=get_translation(lang, 'invalid_credentials'),
                                   lang=lang,
                                   t=get_all_translations(lang),
                                   available_languages=get_available_languages())
        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            return render_template('police_login.html',
                                   error=get_translation(lang, 'login_failed'),
                                   lang=lang,
                                   t=get_all_translations(lang),
                                   available_languages=get_available_languages())

    return render_template('police_login.html',
                           lang=lang,
                           t=get_all_translations(lang),
                           available_languages=get_available_languages())


@app.route('/police/dashboard')
@login_required('police')
def police_dashboard():
    try:
        lang = session.get('language', 'English')
        constituency = session.get('station')
        if not constituency:
            return redirect(url_for('police_login'))

        # Get only reports for this specific constituency
        reports = get_reports_for_station(constituency)
        hotspots = get_hotspots_for_station(constituency)

        # Get constituency-specific statistics
        constituency_stats = get_constituency_statistics(constituency)

        return render_template('police_dashboard.html',
                               station=constituency,
                               reports=reports,
                               hotspots=hotspots,
                               density_data=calculate_hotspot_density(hotspots),
                               trends=analyze_trends(reports),
                               anomalies=detect_anomalies(reports),
                               recommendations=generate_patrol_recommendations(hotspots, reports, constituency),
                               stats=constituency_stats,
                               lang=lang,
                               t=get_all_translations(lang),
                               available_languages=get_available_languages())
    except Exception as e:
        logger.error(f"Dashboard error: {str(e)}")
        return render_template('error.html', message="Failed to load dashboard", code=500), 500


@app.route('/police/respond/<report_id>', methods=['POST'])
@login_required('police')
def police_respond(report_id):
    try:
        constituency = session.get('station')
        officer_name = sanitize_input(request.form.get('officer_name', ''), 200)
        action_taken = sanitize_input(request.form.get('action_taken', ''), 500)
        notes = sanitize_input(request.form.get('notes', ''), 1000)
        status = sanitize_input(request.form.get('status', ''), 50)

        if not all([officer_name, action_taken, status]) or status not in ['pending', 'investigating', 'resolved',
                                                                           'closed']:
            return jsonify({'error': 'Invalid input'}), 400

        update_report_response(report_id, constituency, officer_name, notes, status, action_taken)
        add_audit_log('police', session['username'], f'Responded to #{report_id}', f'Status: {status}', get_client_ip())

        return redirect(url_for('police_dashboard'))

    except Exception as e:
        logger.error(f"Response error: {str(e)}")
        return jsonify({'error': 'Failed to submit'}), 500


@app.route('/police/logout')
def police_logout():
    add_audit_log('police', session.get('username', 'unknown'), 'Logged out', None, get_client_ip())
    session.clear()
    return redirect(url_for('home'))


@app.route('/police/map')
@login_required('police')
def police_map():
    try:
        lang = session.get('language', 'English')
        constituency = session.get('station')
        if not constituency:
            return redirect(url_for('police_login'))

        hotspots = get_hotspots_for_station(constituency)
        center_lat = sum(h.get('lat', 0) for h in hotspots) / len(hotspots) if hotspots else -0.3031
        center_lon = sum(h.get('lon', 0) for h in hotspots) / len(hotspots) if hotspots else 36.0800

        import json
        hotspots_json = json.dumps([{
            'location': h.get('location', 'Unknown'),
            'lat': h.get('lat', 0),
            'lon': h.get('lon', 0),
            'incident_count': h.get('incident_count', 0),
            'last_incident': str(h.get('last_incident', ''))
        } for h in hotspots])

        return render_template('map.html',
                               station=constituency,
                               hotspots=hotspots,
                               hotspots_json=hotspots_json,
                               center_lat=center_lat,
                               center_lon=center_lon,
                               lang=lang,
                               t=get_all_translations(lang))
    except Exception as e:
        logger.error(f"Map error: {str(e)}")
        return render_template('error.html', message="Failed to load map", code=500), 500


@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    lang = get_user_language()

    if request.method == 'POST':
        try:
            username = sanitize_input(request.form.get('username', ''), 100)
            password = request.form.get('password', '')

            credentials = verify_admin_credentials(username, password)
            if credentials:
                session.permanent = True
                session['admin_logged_in'] = True
                session['username'] = username
                session['admin_id'] = credentials['admin_id']
                add_audit_log('admin', username, 'Logged in', None, get_client_ip())
                return redirect(url_for('admin_dashboard'))

            return render_template('admin_login.html',
                                   error=get_translation(lang, 'invalid_credentials'),
                                   lang=lang,
                                   t=get_all_translations(lang),
                                   available_languages=get_available_languages())
        except Exception as e:
            logger.error(f"Admin login error: {str(e)}")
            return render_template('admin_login.html',
                                   error=get_translation(lang, 'login_failed'),
                                   lang=lang,
                                   t=get_all_translations(lang),
                                   available_languages=get_available_languages())

    return render_template('admin_login.html',
                           lang=lang,
                           t=get_all_translations(lang),
                           available_languages=get_available_languages())


@app.route('/admin/dashboard')
@login_required('admin')
def admin_dashboard():
    try:
        lang = get_user_language()
        return render_template('admin_dashboard.html',
                               stats=get_system_statistics(),
                               stations=get_all_police_stations(),
                               settings=get_system_settings(),
                               lang=lang,
                               t=get_all_translations(lang),
                               available_languages=get_available_languages())
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        return render_template('error.html', message="Failed to load dashboard", code=500), 500


@app.route('/admin/add_station', methods=['POST'])
@login_required('admin')
def admin_add_station():
    try:
        constituency = sanitize_input(request.form.get('constituency', ''), 100)
        username = sanitize_input(request.form.get('username', ''), 100)
        password = request.form.get('password', '')
        preferred_language = sanitize_input(request.form.get('preferred_language', 'English'), 50)
        contact_phone = sanitize_input(request.form.get('contact_phone', ''), 20)
        contact_email = sanitize_input(request.form.get('contact_email', ''), 100)

        if not all([constituency, username, password]) or len(password) < 8:
            return jsonify({'error': 'Invalid input'}), 400

        add_police_station(constituency, username, password, preferred_language, contact_phone, contact_email)
        add_audit_log('admin', session['username'], f'Added station: {constituency}', None, get_client_ip())

        return redirect(url_for('admin_dashboard'))
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        return jsonify({'error': 'Failed to add station'}), 500


@app.route('/admin/update_station/<station_id>', methods=['POST'])
@login_required('admin')
def admin_update_station(station_id):
    try:
        constituency = sanitize_input(request.form.get('constituency', ''), 100)
        username = sanitize_input(request.form.get('username', ''), 100)
        password = request.form.get('password', '')
        preferred_language = sanitize_input(request.form.get('preferred_language', 'English'), 50)
        contact_phone = sanitize_input(request.form.get('contact_phone', ''), 20)
        contact_email = sanitize_input(request.form.get('contact_email', ''), 100)

        password_hash = generate_password_hash(password) if password else None
        if password and len(password) < 8:
            return jsonify({'error': 'Password must be 8+ characters'}), 400

        update_police_station(station_id, constituency, username, password_hash, preferred_language, contact_phone,
                              contact_email)
        add_audit_log('admin', session['username'], f'Updated station ID: {station_id}', None, get_client_ip())

        return redirect(url_for('admin_dashboard'))
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        return jsonify({'error': 'Failed to update'}), 500


@app.route('/admin/deactivate_station/<station_id>', methods=['POST'])
@login_required('admin')
def admin_deactivate_station(station_id):
    try:
        deactivate_police_station(station_id)
        add_audit_log('admin', session['username'], f'Deactivated station ID: {station_id}', None, get_client_ip())
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/admin/activate_station/<station_id>', methods=['POST'])
@login_required('admin')
def admin_activate_station(station_id):
    try:
        activate_police_station(station_id)
        add_audit_log('admin', session['username'], f'Activated station ID: {station_id}', None, get_client_ip())
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/admin/audit_logs')
@login_required('admin')
def admin_audit_logs():
    try:
        lang = get_user_language()
        user_type = request.args.get('user_type')
        logs = get_audit_logs(limit=1000, user_type=user_type)
        return render_template('audit_logs.html',
                               logs=logs,
                               lang=lang,
                               t=get_all_translations(lang),
                               available_languages=get_available_languages())
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        return render_template('error.html', message="Failed to load logs", code=500), 500


@app.route('/admin/settings', methods=['GET', 'POST'])
@login_required('admin')
def admin_settings():
    lang = get_user_language()

    if request.method == 'POST':
        try:
            categories = [c.strip() for c in request.form.get('categories', '').split(',') if c.strip()]
            languages = [l.strip() for l in request.form.get('languages', '').split(',') if l.strip()]
            spam_threshold = int(request.form.get('spam_threshold', 60))
            auto_reject_threshold = int(request.form.get('auto_reject_threshold', 85))

            if not categories or not languages or not (0 <= spam_threshold <= 100) or not (
                    0 <= auto_reject_threshold <= 100):
                return jsonify({'error': 'Invalid settings'}), 400

            update_system_settings(categories, languages, spam_threshold, auto_reject_threshold)
            add_audit_log('admin', session['username'], 'Updated settings', None, get_client_ip())

            return redirect(url_for('admin_dashboard'))
        except Exception as e:
            logger.error(f"Error: {str(e)}")
            return jsonify({'error': 'Failed to update'}), 500

    return render_template('admin_settings.html',
                           settings=get_system_settings(),
                           lang=lang,
                           t=get_all_translations(lang),
                           available_languages=get_available_languages())


@app.route('/admin/logout')
def admin_logout():
    add_audit_log('admin', session.get('username', 'unknown'), 'Logged out', None, get_client_ip())
    session.clear()
    return redirect(url_for('home'))


@app.route('/api/track_report/<report_id>')
def api_track_report(report_id):
    """API endpoint to track a report by ID."""
    try:
        from bson.objectid import ObjectId

        # Try to find by full ObjectId or short ID
        report = None

        # First try as full ObjectId
        if len(report_id) == 24:
            try:
                report = reports_col.find_one({'_id': ObjectId(report_id)})
            except:
                pass

        # If not found, search by short ID (last 8 characters)
        if not report:
            all_reports = list(reports_col.find({}).sort('created_at', -1).limit(100))
            for r in all_reports:
                if str(r['_id'])[-8:] == report_id:
                    report = r
                    break

        if not report:
            return jsonify({'success': False, 'message': 'Report not found'}), 404

        # Get response if exists
        response = responses_col.find_one({'report_id': report['_id']})

        report_data = {
            'short_id': str(report['_id'])[-8:],
            'category': report.get('category', 'N/A'),
            'manual_location': report.get('manual_location', 'N/A'),
            'constituency': report.get('constituency', 'N/A'),
            'status': report.get('status', 'pending'),
            'created_at': report.get('created_at', datetime.now()).isoformat(),
            'officer_name': response.get('officer_name') if response else None,
            'action_taken': response.get('action_taken') if response else None,
            'notes': response.get('notes') if response else None
        }

        return jsonify({'success': True, 'report': report_data})

    except Exception as e:
        logger.error(f"Track report error: {str(e)}")
        return jsonify({'success': False, 'message': 'Error tracking report'}), 500


@app.route('/api/stats')
def api_stats():
    try:
        return jsonify(get_system_statistics())
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/health')
def api_health():
    try:
        get_system_statistics()
        return jsonify({'status': 'healthy', 'timestamp': datetime.now().isoformat()})
    except Exception as e:
        return jsonify({'status': 'unhealthy', 'error': str(e)}), 500


@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', message="Page not found", code=404), 404


@app.errorhandler(500)
def server_error(e):
    logger.error(f"500: {str(e)}")
    return render_template('error.html', message="Internal error", code=500), 500


@app.errorhandler(413)
def file_too_large(e):
    return jsonify({'error': 'File exceeds 10MB'}), 413


@app.errorhandler(400)
def bad_request(e):
    return jsonify({'error': 'Bad request'}), 400


@app.context_processor
def inject_globals():
    return {
        'now': datetime.now(),
        'app_name': 'Incident Reporting System',
        'get_translation': lambda key: get_translation(session.get('language', 'English'), key),
        'current_lang': session.get('language', 'English')
    }


@app.before_request
def before_request():
    session.permanent = True
    if 'language' not in session:
        session['language'] = 'English'


if __name__ == '__main__':
    if os.environ.get('FLASK_ENV') == 'production':
        app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
    else:
        app.run(host='0.0.0.0', port=5000, debug=True)