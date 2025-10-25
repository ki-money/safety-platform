import numpy as np
from scipy.cluster.hierarchy import linkage, fcluster
from scipy.spatial.distance import pdist
from datetime import datetime, timedelta
import re
import logging
from database import get_system_settings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def perform_clustering(hotspots, distance_threshold=0.01):
    """Perform hierarchical clustering on GPS coordinates."""
    if len(hotspots) < 2:
        return list(zip(hotspots, [0] * len(hotspots)))
    try:
        data = np.array(hotspots, dtype=np.float64)
        dist_matrix = pdist(data, metric='euclidean')
        clusters = linkage(dist_matrix, method='ward')
        labels = fcluster(clusters, t=distance_threshold, criterion='distance')
        return list(zip(hotspots, labels.tolist()))
    except Exception as e:
        logger.error(f"Clustering error: {str(e)}")
        return list(zip(hotspots, [0] * len(hotspots)))


def detect_spam(report_data):
    """Advanced spam detection with multilingual support."""
    settings = get_system_settings()
    spam_threshold = min(max(settings.get('spam_threshold', 60), 0), 100)
    spam_score = 0
    spam_indicators = []

    description = str(report_data.get('description', '')).lower()
    location = str(report_data.get('manual_location', '')).lower()
    language = report_data.get('language', 'English')

    # Multilingual test/spam keywords
    test_keywords = {
        'English': r'\b(test|testing|asdf|qwerty|spam|fake|xxx|dummy|sample)\b',
        'Kiswahili': r'\b(jaribio|majaribio|bandia|uwongo|fake|test)\b',
        'Kikuyu': r'\b(kũgeria|kũgeragia|ũtaga|test|fake)\b'
    }
    
    # Multilingual promotional keywords
    promo_keywords = {
        'English': r'(buy|sale|discount|click\s*here|www\.|http|offer|deal|cheap)',
        'Kiswahili': r'(nunua|uza|punguzo|bonyeza\s*hapa|bei\s*nafuu|ofa)',
        'Kikuyu': r'(gũra|kũgũra|bei\s*nini|www\.|http)'
    }

    if len(description) < 20:
        spam_score += 40
        spam_indicators.append("Description too short")
    
    # Check test/spam keywords in user's language
    test_pattern = test_keywords.get(language, test_keywords['English'])
    if re.search(test_pattern, description):
        spam_score += 50
        spam_indicators.append("Contains test/spam keywords")
    
    # Check promotional content in user's language
    promo_pattern = promo_keywords.get(language, promo_keywords['English'])
    if re.search(promo_pattern, description, re.IGNORECASE):
        spam_score += 50
        spam_indicators.append("Promotional content detected")
    
    if not location or len(location) < 3:
        spam_score += 30
        spam_indicators.append("Invalid location")

    lat, lon = report_data.get('lat'), report_data.get('lon')
    if lat and lon:
        try:
            lat_f, lon_f = float(lat), float(lon)
            if not (-1.2 <= lat_f <= 0.2 and 35.7 <= lon_f <= 36.5):
                spam_score += 30
                spam_indicators.append("Location outside Nakuru County")
        except ValueError:
            spam_score += 20
            spam_indicators.append("Invalid GPS coordinates")

    is_spam = spam_score >= spam_threshold
    return {
        'is_spam': is_spam,
        'spam_score': spam_score,
        'confidence': min(spam_score / 100, 1.0),
        'reasons': spam_indicators,
        'action': 'reject' if spam_score >= settings.get('auto_reject_threshold', 80) else (
            'review' if is_spam else 'accept')
    }


def detect_anomalies(reports):
    """Detect urgent/critical reports with multilingual support."""
    if not reports or len(reports) < 3:
        return []
    try:
        anomalies = []
        
        # Multilingual critical keywords
        critical_keywords = {
            'English': ['murder', 'rape', 'gun', 'weapon', 'kill', 'death', 'bomb', 'shot', 'shooting'],
            'Kiswahili': ['mauaji', 'ubakaji', 'bunduki', 'silaha', 'kuua', 'kifo', 'bomu', 'risasi'],
            'Kikuyu': ['kũũraga', 'gũthemba', 'mbaci', 'gĩkuũ', 'mabomu']
        }
        
        # Multilingual urgent keywords
        urgent_keywords = {
            'English': ['emergency', 'urgent', 'help', 'attack', 'violence', 'fire', 'accident', 'danger'],
            'Kiswahili': ['dharura', 'haraka', 'msaada', 'shambulio', 'jeuri', 'moto', 'ajali', 'hatari'],
            'Kikuyu': ['thĩĩna', 'haraka', 'ũteithio', 'kũgũtha', 'haaro', 'mwaki', 'mũtino']
        }

        for report in reports:
            urgency_score = 0
            description = str(report.get('description', '')).lower()
            language = report.get('language', 'English')

            # Check critical keywords for the report's language
            for lang in critical_keywords:
                pattern = r'\b(' + '|'.join(critical_keywords[lang]) + r')\b'
                if re.search(pattern, description):
                    urgency_score += 70
                    break
            
            # Check urgent keywords if not already critical
            if urgency_score < 70:
                for lang in urgent_keywords:
                    pattern = r'\b(' + '|'.join(urgent_keywords[lang]) + r')\b'
                    if re.search(pattern, description):
                        urgency_score += 40
                        break
            
            if description.count('!') >= 2:
                urgency_score += 10
            
            # Time-sensitive indicators (multilingual)
            time_patterns = {
                'English': r'\b(now|currently|happening|ongoing)\b',
                'Kiswahili': r'\b(sasa|inaendelea|inatokea)\b',
                'Kikuyu': r'\b(rĩu|rĩrĩa|kũgĩĩka)\b'
            }
            
            for lang, pattern in time_patterns.items():
                if re.search(pattern, description):
                    urgency_score += 20
                    break

            if urgency_score >= 40:
                anomalies.append({
                    'report': report,
                    'urgency_score': min(urgency_score, 100),
                    'priority': 'CRITICAL' if urgency_score >= 70 else 'HIGH'
                })

        anomalies.sort(key=lambda x: x['urgency_score'], reverse=True)
        return anomalies
    except Exception as e:
        logger.error(f"Anomaly detection error: {str(e)}")
        return []


def calculate_hotspot_density(hotspots, radius=0.005):
    """Calculate density of incidents at each location."""
    settings = get_system_settings()
    thresholds = {
        'critical': settings.get('critical_density_threshold', 10),
        'high': settings.get('high_density_threshold', 6),
        'medium': settings.get('medium_density_threshold', 3)
    }

    if not hotspots:
        return []

    coords = []
    valid_hotspots = []
    for h in hotspots:
        try:
            lat, lon = float(h.get('lat', 0)), float(h.get('lon', 0))
            if (-90 <= lat <= 90) and (-180 <= lon <= 180):
                coords.append([lat, lon])
                valid_hotspots.append(h)
        except (ValueError, TypeError):
            continue

    if not coords:
        return [{'hotspot': h, 'lat': h.get('lat', 0), 'lon': h.get('lon', 0), 'density': 1, 'risk_level': 'LOW'} for h
                in hotspots]

    try:
        data = np.array(coords, dtype=np.float64)
        density = []

        for i, point in enumerate(data):
            distances = np.sqrt(np.sum((data - point) ** 2, axis=1))
            point_density = int(np.sum(distances <= radius))

            if point_density >= thresholds['critical']:
                risk_level = 'CRITICAL'
            elif point_density >= thresholds['high']:
                risk_level = 'HIGH'
            elif point_density >= thresholds['medium']:
                risk_level = 'MEDIUM'
            else:
                risk_level = 'LOW'

            density.append({
                'hotspot': valid_hotspots[i],
                'lat': point[0],
                'lon': point[1],
                'density': point_density,
                'risk_level': risk_level
            })

        density.sort(key=lambda x: x['density'], reverse=True)
        return density
    except Exception as e:
        logger.error(f"Density calculation error: {str(e)}")
        return [{'hotspot': h, 'lat': h.get('lat', 0), 'lon': h.get('lon', 0), 'density': 1, 'risk_level': 'LOW'} for h
                in hotspots]


def analyze_trends(reports, time_window_days=7):
    """Analyze reporting trends."""
    settings = get_system_settings()
    time_window_days = settings.get('trend_time_window', time_window_days)

    if not reports:
        return {'total': 0, 'recent': 0, 'trend': 'stable', 'categories': {}, 'peak_hour': 12,
                'most_common_category': 'N/A'}

    try:
        now = datetime.now()
        cutoff = now - timedelta(days=time_window_days)
        recent_reports = []
        category_counts = {}
        hourly_distribution = [0] * 24

        for report in reports:
            try:
                timestamp = datetime.fromisoformat(str(report.get('timestamp', now)))
            except ValueError:
                continue

            category = str(report.get('category', 'Unknown'))
            category_counts[category] = category_counts.get(category, 0) + 1
            hourly_distribution[timestamp.hour] += 1

            if timestamp >= cutoff:
                recent_reports.append(report)

        total = len(reports)
        recent = len(recent_reports)
        trend = 'stable'

        if total >= 2:
            recent_rate = recent / time_window_days
            oldest_date = datetime.fromisoformat(str(reports[-1].get('timestamp', now)))
            total_days = max((now - oldest_date).days, 1)
            overall_rate = total / total_days

            if recent_rate > overall_rate * 1.2:
                trend = 'increasing'
            elif recent_rate < overall_rate * 0.8:
                trend = 'decreasing'

        peak_hour = hourly_distribution.index(max(hourly_distribution))

        return {
            'total': total,
            'recent': recent,
            'trend': trend,
            'categories': category_counts,
            'peak_hour': peak_hour,
            'most_common_category': max(category_counts.items(), key=lambda x: x[1])[0] if category_counts else 'N/A'
        }
    except Exception as e:
        logger.error(f"Trend analysis error: {str(e)}")
        return {'total': len(reports), 'recent': 0, 'trend': 'stable', 'categories': {}, 'peak_hour': 12,
                'most_common_category': 'N/A'}


def generate_patrol_recommendations(hotspots, reports, constituency):
    """Generate patrol recommendations based on analysis."""
    try:
        density_data = calculate_hotspot_density(hotspots)
        trends = analyze_trends(reports)
        recommendations = []

        critical_zones = [d for d in density_data if d['risk_level'] == 'CRITICAL']
        if critical_zones:
            recommendations.append({
                'type': 'HIGH_DENSITY_PATROL',
                'priority': 'CRITICAL',
                'locations': critical_zones[:3],
                'message': f'Deploy patrols to {len(critical_zones)} high-density crime zones'
            })

        peak_hour = trends.get('peak_hour', 12)
        recommendations.append({
            'type': 'PEAK_HOUR_COVERAGE',
            'priority': 'HIGH',
            'time': f'{peak_hour:02d}:00 - {(peak_hour + 2) % 24:02d}:00',
            'message': 'Increase presence during peak incident hours'
        })

        most_common = trends.get('most_common_category', 'N/A')
        if most_common != 'N/A':
            recommendations.append({
                'type': 'CATEGORY_FOCUS',
                'priority': 'MEDIUM',
                'category': most_common,
                'message': f'Focus on {most_common} prevention'
            })

        return recommendations
    except Exception as e:
        logger.error(f"Recommendation error: {str(e)}")
        return []
