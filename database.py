from pymongo import MongoClient, ASCENDING, DESCENDING
import logging
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import os

logger = logging.getLogger(__name__)

# MongoDB connection
MONGO_URI = os.environ.get('MONGO_URI', 'mongodb://127.0.0.1:27017/')
client = MongoClient(MONGO_URI)
db = client['citizen_safety']

# Collections
reports_col = db['reports']
stations_col = db['police_stations']
responses_col = db['responses']
hotspots_col = db['hotspots']
audit_logs_col = db['audit_logs']
settings_col = db['system_settings']
admin_col = db['admin_users']


def init_db():
    """Initialize database with indexes and default data."""
    try:
        # Create indexes
        reports_col.create_index([('constituency', ASCENDING)])
        reports_col.create_index([('status', ASCENDING)])
        reports_col.create_index([('created_at', DESCENDING)])
        stations_col.create_index([('constituency', ASCENDING)], unique=True)
        stations_col.create_index([('username', ASCENDING)], unique=True)
        responses_col.create_index([('report_id', ASCENDING)])
        hotspots_col.create_index([('constituency', ASCENDING)])
        audit_logs_col.create_index([('user_type', ASCENDING)])

        # Insert default settings if not exists
        if settings_col.count_documents({}) == 0:
            settings_col.insert_one({
                'categories': ['Theft', 'Assault', 'Vandalism', 'Drug Activity', 'Traffic Violation', 'Other'],
                'languages': ['English', 'Kiswahili', 'Kikuyu', 'Luo', 'Kamba'],
                'spam_threshold': 60,
                'auto_reject_threshold': 85,
                'updated_at': datetime.now()
            })

        # Insert default admin if not exists
        if admin_col.count_documents({}) == 0:
            admin_col.insert_one({
                'username': 'admin_nakuru',
                'password_hash': generate_password_hash('secure_admin_2025'),
                'email': 'admin@system.local',
                'is_active': True,
                'created_at': datetime.now()
            })

        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Database initialization error: {str(e)}")


def migrate_schema():
    """Placeholder for schema migrations."""
    logger.info("Schema migration completed")


def get_all_constituencies():
    """Get all active constituencies as a list of tuples."""
    return [(station['constituency'],) for station in
            stations_col.find({'is_active': True}, {'constituency': 1})
            .sort('constituency', ASCENDING)]


def update_report_response(report_id, constituency, officer_name, notes, status, action_taken):
    """Update report with police response."""
    from bson.objectid import ObjectId

    report = reports_col.find_one({'_id': ObjectId(report_id)})
    if not report or report['constituency'] != constituency:
        raise ValueError("Report does not belong to this constituency")

    station = stations_col.find_one({'constituency': constituency, 'is_active': True})
    if not station:
        raise ValueError(f"No active police station found for constituency {constituency}")

    # Update report status
    reports_col.update_one(
        {'_id': ObjectId(report_id)},
        {'$set': {'status': status, 'updated_at': datetime.now()}}
    )

    # Add response record
    responses_col.insert_one({
        'report_id': ObjectId(report_id),
        'station_id': station['_id'],
        'officer_name': officer_name,
        'action_taken': action_taken,
        'notes': notes,
        'status': status,
        'created_at': datetime.now()
    })


def add_police_station(constituency, username, password, preferred_language, contact_phone, contact_email):
    """Add a new police station."""
    stations_col.insert_one({
        'constituency': constituency,
        'username': username,
        'password_hash': generate_password_hash(password),
        'preferred_language': preferred_language,
        'contact_phone': contact_phone,
        'contact_email': contact_email,
        'is_active': True,
        'created_at': datetime.now(),
        'updated_at': datetime.now()
    })


def update_police_station(station_id, constituency, username, password_hash, preferred_language, contact_phone,
                          contact_email):
    """Update police station details."""
    from bson.objectid import ObjectId

    update_data = {
        'constituency': constituency,
        'username': username,
        'preferred_language': preferred_language,
        'contact_phone': contact_phone,
        'contact_email': contact_email,
        'updated_at': datetime.now()
    }

    if password_hash:
        update_data['password_hash'] = password_hash

    stations_col.update_one({'_id': ObjectId(station_id)}, {'$set': update_data})


def verify_police_credentials(username, password):
    """Verify police login credentials."""
    user = stations_col.find_one({'username': username, 'is_active': True})
    if user and check_password_hash(user['password_hash'], password):
        return {
            'constituency': user['constituency'],
            'preferred_language': user.get('preferred_language', 'English')
        }
    return None


def verify_admin_credentials(username, password):
    """Verify admin login credentials."""
    user = admin_col.find_one({'username': username, 'is_active': True})
    if user and check_password_hash(user['password_hash'], password):
        return {'admin_id': str(user['_id'])}
    return None


def get_all_police_stations():
    """Get all police stations."""
    stations = list(stations_col.find({}).sort('constituency', ASCENDING))
    for station in stations:
        station['id'] = str(station['_id'])
    return stations


def deactivate_police_station(station_id):
    """Deactivate a police station."""
    from bson.objectid import ObjectId
    stations_col.update_one({'_id': ObjectId(station_id)}, {'$set': {'is_active': False, 'updated_at': datetime.now()}})


def activate_police_station(station_id):
    """Activate a police station."""
    from bson.objectid import ObjectId
    stations_col.update_one({'_id': ObjectId(station_id)}, {'$set': {'is_active': True, 'updated_at': datetime.now()}})


def add_audit_log(user_type, username, action, details=None, ip_address=None):
    """Add an audit log entry."""
    try:
        audit_logs_col.insert_one({
            'user_type': user_type,
            'username': username,
            'action': action,
            'details': details,
            'ip_address': ip_address,
            'created_at': datetime.now()
        })
    except Exception as e:
        logger.error(f"Failed to add audit log: {str(e)}")


def get_audit_logs(limit=100, user_type=None):
    """Get audit logs with optional filtering."""
    query = {'user_type': user_type} if user_type else {}
    logs = list(audit_logs_col.find(query).sort('created_at', -1).limit(limit))
    for log in logs:
        log['id'] = str(log['_id'])
    return logs


def get_system_settings():
    """Get current system settings."""
    settings = settings_col.find_one({})
    if settings:
        return {
            'categories': settings.get('categories', []),
            'languages': settings.get('languages', []),
            'spam_threshold': settings.get('spam_threshold', 60),
            'auto_reject_threshold': settings.get('auto_reject_threshold', 85)
        }
    return {}


def update_system_settings(categories, languages, spam_threshold, auto_reject_threshold):
    """Update system settings."""
    settings_col.update_one(
        {},
        {
            '$set': {
                'categories': categories,
                'languages': languages,
                'spam_threshold': spam_threshold,
                'auto_reject_threshold': auto_reject_threshold,
                'updated_at': datetime.now()
            }
        },
        upsert=True
    )


def get_constituency_statistics(constituency):
    """Get statistics for a specific constituency."""
    total_reports = reports_col.count_documents({'constituency': constituency})
    pending_reports = reports_col.count_documents({'constituency': constituency, 'status': 'pending'})
    resolved_reports = reports_col.count_documents({'constituency': constituency, 'status': {'$in': ['resolved', 'closed']}})

    yesterday = datetime.now() - timedelta(days=1)
    recent_reports = reports_col.count_documents({'constituency': constituency, 'created_at': {'$gte': yesterday}})

    # Average response time for this constituency
    thirty_days_ago = datetime.now() - timedelta(days=30)
    pipeline = [
        {'$match': {'constituency': constituency, 'created_at': {'$gte': thirty_days_ago}}},
        {'$lookup': {
            'from': 'responses',
            'localField': '_id',
            'foreignField': 'report_id',
            'as': 'response'
        }},
        {'$unwind': '$response'},
        {'$project': {
            'response_time': {
                '$divide': [
                    {'$subtract': ['$response.created_at', '$created_at']},
                    3600000  # Convert to hours
                ]
            }
        }},
        {'$group': {
            '_id': None,
            'avg_response_time': {'$avg': '$response_time'}
        }}
    ]

    result = list(reports_col.aggregate(pipeline))
    avg_response = round(result[0]['avg_response_time'], 2) if result else 0

    return {
        'total_reports': total_reports,
        'pending_reports': pending_reports,
        'resolved_reports': resolved_reports,
        'recent_reports': recent_reports,
        'avg_response_time': avg_response
    }


def get_system_statistics():
    """Get system-wide statistics."""
    total_reports = reports_col.count_documents({})
    pending_reports = reports_col.count_documents({'status': 'pending'})
    resolved_reports = reports_col.count_documents({'status': {'$in': ['resolved', 'closed']}})
    active_stations = stations_col.count_documents({'is_active': True})

    yesterday = datetime.now() - timedelta(days=1)
    recent_reports = reports_col.count_documents({'created_at': {'$gte': yesterday}})

    # Average response time
    thirty_days_ago = datetime.now() - timedelta(days=30)
    pipeline = [
        {'$match': {'created_at': {'$gte': thirty_days_ago}}},
        {'$lookup': {
            'from': 'responses',
            'localField': '_id',
            'foreignField': 'report_id',
            'as': 'response'
        }},
        {'$unwind': '$response'},
        {'$project': {
            'response_time': {
                '$divide': [
                    {'$subtract': ['$response.created_at', '$created_at']},
                    3600000  # Convert to hours
                ]
            }
        }},
        {'$group': {
            '_id': None,
            'avg_response_time': {'$avg': '$response_time'}
        }}
    ]

    result = list(reports_col.aggregate(pipeline))
    avg_response = round(result[0]['avg_response_time'], 2) if result else 0

    return {
        'total_reports': total_reports,
        'pending_reports': pending_reports,
        'resolved_reports': resolved_reports,
        'active_stations': active_stations,
        'recent_reports': recent_reports,
        'avg_response_time': avg_response
    }


def add_report(category, description, manual_location, lat, lon, constituency, language, media_path, spam_result):
    """Add a new incident report."""
    report = {
        'category': category,
        'description': description,
        'manual_location': manual_location,
        'lat': lat,
        'lon': lon,
        'constituency': constituency,
        'language': language,
        'media_path': media_path,
        'spam_score': spam_result['spam_score'],
        'spam_reasons': spam_result.get('reasons', []),
        'status': 'pending',
        'created_at': datetime.now(),
        'updated_at': datetime.now()
    }
    result = reports_col.insert_one(report)

    # Update or create hotspot
    hotspot = hotspots_col.find_one({'constituency': constituency, 'location': manual_location})
    if hotspot:
        hotspots_col.update_one(
            {'_id': hotspot['_id']},
            {
                '$inc': {'incident_count': 1},
                '$set': {'last_incident': datetime.now()}
            }
        )
    else:
        hotspots_col.insert_one({
            'constituency': constituency,
            'location': manual_location,
            'lat': lat,
            'lon': lon,
            'incident_count': 1,
            'last_incident': datetime.now(),
            'created_at': datetime.now()
        })

    return result.inserted_id


def get_reports_for_station(constituency):
    """Get all reports for a specific constituency ONLY."""
    if not constituency:
        raise ValueError("Constituency is required")

    station = stations_col.find_one({'constituency': constituency, 'is_active': True})
    if not station:
        raise ValueError(f"No active police station found for constituency {constituency}")

    # CRITICAL: Filter by constituency to show only reports from this constituency
    pipeline = [
        {'$match': {'constituency': constituency}},  # This ensures only constituency reports are shown
        {'$sort': {'created_at': -1}},
        {'$limit': 500},
        {'$lookup': {
            'from': 'responses',
            'localField': '_id',
            'foreignField': 'report_id',
            'as': 'response'
        }},
        {'$unwind': {'path': '$response', 'preserveNullAndEmptyArrays': True}}
    ]

    reports = list(reports_col.aggregate(pipeline))
    for report in reports:
        report['id'] = str(report['_id'])
        # Show short report ID for display
        report['short_id'] = str(report['_id'])[-8:]
        if 'response' in report:
            report['officer_name'] = report['response'].get('officer_name')
            report['action_taken'] = report['response'].get('action_taken')
            report['notes'] = report['response'].get('notes')
            report['response_time'] = report['response'].get('created_at')

    return reports


def get_hotspots_for_station(constituency):
    """Get hotspots for a specific constituency."""
    station = stations_col.find_one({'constituency': constituency, 'is_active': True})
    if not station:
        return []

    hotspots = list(
        hotspots_col.find({'constituency': constituency})
        .sort([('incident_count', -1), ('last_incident', -1)])
        .limit(100)
    )
    for hotspot in hotspots:
        hotspot['id'] = str(hotspot['_id'])

    return hotspots