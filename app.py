import os
import math
import functools
import requests
import logging
import polyline
import json

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from datetime import datetime, timedelta, timezone
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import (
    create_access_token, JWTManager, jwt_required,
    get_jwt_identity, get_jwt
)

# --- Flask App Initialization ---
app = Flask(__name__)
CORS(app) # Enable CORS for all routes

# --- Logging Configuration ---
# Configure logging to show errors in the console
if app.debug:
    logging.basicConfig(level=logging.DEBUG)
else:
    logging.basicConfig(level=logging.INFO)

# --- Database Configuration ---
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
# Changed database name from koerebog.db to tuxtrip.db for consistency
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'tuxtrip.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False # Suppress warning
db = SQLAlchemy(app)

# --- JWT Configuration ---
app.config["JWT_SECRET_KEY"] = "your-super-secret-key-you-must-change-in-" # !!! CHANGE THIS IN PRODUCTION !!!
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=24) # Tokens expire after 24 hours
jwt = JWTManager(app)

# JWT custom claims (to include is_admin in the token)
@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    # Flask-JWT-Extended expects 'sub' (subject) to be a string
    identity = str(jwt_data["sub"]) # Ensure identity is always a string
    return User.query.filter_by(id=identity).first()

@jwt.additional_claims_loader
def add_claims_to_access_token(identity):
    user = User.query.get(identity) # identity is already str here
    if user:
        return {"is_admin": user.is_admin}
    return {"is_admin": False}

# --- Custom Decorator for Admin Required ---
def admin_required():
    def wrapper(fn):
        @functools.wraps(fn)
        @jwt_required()
        def decorated_view(*args, **kwargs):
            claims = get_jwt()
            if claims and claims.get("is_admin"): # Check if claims exist and is_admin is True
                return fn(*args, **kwargs)
            else:
                return jsonify(message="Administrator rights required"), 403
        return decorated_view
    return wrapper

# --- Database Models ---

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        # Correct order for check_password_hash
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'is_admin': self.is_admin
        }

    def __repr__(self):
        return f'<User {self.username}>'

class Location(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    address = db.Column(db.String(200))
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))

    user = db.relationship('User', backref=db.backref('locations', lazy=True))

    def __repr__(self):
        return f'<Location {self.name}>'

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'name': self.name,
            'address': self.address,
            'latitude': self.latitude,
            'longitude': self.longitude,
            'description': self.description,
            'created_at': self.created_at.isoformat()
        }

class Trip(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    start_location_id = db.Column(db.Integer, db.ForeignKey('location.id'), nullable=False)
    end_location_id = db.Column(db.Integer, db.ForeignKey('location.id'), nullable=False)
    purpose = db.Column(db.String(200), nullable=False)
    notes = db.Column(db.Text, nullable=True) # Kept as a common feature for logbooks
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    distance_km = db.Column(db.Float, nullable=True) # Calculated and stored in km

    # Relationships
    user = db.relationship('User', backref=db.backref('trips', lazy=True))
    start_location = db.relationship('Location', foreign_keys=[start_location_id])
    end_location = db.relationship('Location', foreign_keys=[end_location_id])

    def __repr__(self):
        return f'<Trip {self.date} {self.purpose}>'

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'date': self.date.isoformat(),
            'start_location_id': self.start_location_id,
            'start_location': self.start_location.to_dict() if self.start_location else None,
            'end_location_id': self.end_location_id,
            'end_location': self.end_location.to_dict() if self.end_location else None,
            'purpose': self.purpose,
            'notes': self.notes,
            'created_at': self.created_at.isoformat(),
            'distance_km': self.distance_km
        }

# --- Database Initialization ---
with app.app_context():
    db.create_all()

    # Create an admin user if one doesn't exist
    if not User.query.filter_by(username='admin').first():
        admin_user = User(username='admin', is_admin=True)
        admin_user.set_password('adminpass') # !!! CHANGE THIS DEFAULT PASSWORD IMMEDIATELY !!!
        db.session.add(admin_user)
        db.session.commit()
        print("Default admin user 'admin' created with password 'adminpass'")
    else:
        print("Admin user 'admin' already exists.")

# --- Utility Functions ---

NOMINATIM_URL = "http://localhost:8080/search" # Your Nominatim container
OSRM_URL = "http://localhost:5001/route/v1/driving" # Your OSRM container
OSRM_BASE_URL = "http://localhost:5001" # Your OSRM base URL

def lookup_address_nominatim(query): # Renamed 'address' to 'query' for clarity
    params = {
        "q": query,
        "format": "json",
        "limit": 5 # Limit to 5 suggestions for autocomplete
    }
    try:
        response = requests.get(NOMINATIM_URL, params=params)
        response.raise_for_status() # Raise an exception for HTTP errors
        data = response.json()
        
        suggestions = []
        for item in data:
            suggestions.append({
                "place_id": item.get("place_id"), # Unique ID from Nominatim
                "display_name": item.get("display_name"),
                "latitude": float(item.get("lat")),
                "longitude": float(item.get("lon"))
            })
        return suggestions # Return a list of dictionaries

    except requests.exceptions.RequestException as e:
        app.logger.error(f"Nominatim API error: {e}")
        return [] # Return empty list on error
    except Exception as e:
        app.logger.error(f"Error parsing Nominatim data: {e}")
        return [] # Return empty list on error

def get_route_distance_osrm(start_lat, start_lon, end_lat, end_lon):
    """
    Fetches route data from OSRM.
    Returns a dictionary with 'distance_meters' and 'geometry_encoded' (OSRM polyline string).
    Returns None if route cannot be found or on error.
    """
    # OSRM expects coordinates as longitude,latitude
    coords = f"{start_lon},{start_lat};{end_lon},{end_lat}"
    # Change overview=false to overview=full to get the polyline geometry
    url = f"{OSRM_URL}/{coords}?overview=full"

    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        if data and data['code'] == 'Ok' and data['routes']:
            return {
                "distance_meters": data['routes'][0]['distance'], # Distance in meters
                "geometry_encoded": data['routes'][0]['geometry'] # Polyline encoded string
            }
        return None
    except requests.exceptions.RequestException as e:
        app.logger.error(f"OSRM API error: {e}")
        return None
    except Exception as e:
        app.logger.error(f"Error parsing OSRM data: {e}")
        return None

@app.route('/api/route-data', methods=['GET'])
@jwt_required()
def get_route_data():
    start_lat = request.args.get('start_lat', type=float)
    start_lon = request.args.get('start_lon', type=float)
    end_lat = request.args.get('end_lat', type=float)
    end_lon = request.args.get('end_lon', type=float)

    if None in [start_lat, start_lon, end_lat, end_lon]:
        return jsonify({"message": "Missing start/end coordinates"}), 400

    # Call the modified OSRM function
    osrm_result = get_route_distance_osrm(start_lat, start_lon, end_lat, end_lon)

    if osrm_result:
        # Use your existing calculate_distance for the actual distance shown to user
        # This ensures consistency with how distances are stored for trips.
        calculated_distance_km = calculate_distance(start_lat, start_lon, end_lat, end_lon)

        # Decode the polyline geometry for the frontend
        decoded_geometry = polyline.decode(osrm_result["geometry_encoded"])

        return jsonify({
            "distance_km": calculated_distance_km, # Use your haversine distance
            "geometry": decoded_geometry # List of [lat, lon] pairs
        }), 200
    else:
        return jsonify({"message": "Could not get route data from OSRM"}), 500

def calculate_distance(lat1, lon1, lat2, lon2):
    R = 6371.0  # Radius of the Earth in kilometers

    lat1_rad = math.radians(lat1)
    lon1_rad = math.radians(lon1)
    lat2_rad = math.radians(lat2)
    lon2_rad = math.radians(lon2)

    dlon = lon2_rad - lon1_rad
    dlat = lat2_rad - lat1_rad

    a = math.sin(dlat / 2)**2 + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(dlon / 2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

    distance = R * c
    return round(distance, 2) # Round to 2 decimals

# --- API Endpoints ---

# Public login endpoint
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()

    if user and user.check_password(password):
        # The JWT token will now automatically include 'is_admin' claim
        access_token = create_access_token(identity=str(user.id)) # Ensure identity is a string
        return jsonify(access_token=access_token, username=user.username, is_admin=user.is_admin), 200
    else:
        return jsonify({"message": "Incorrect username or password"}), 401

# Admin API Endpoints
@app.route('/api/admin/users', methods=['POST'])
@admin_required() # Only admins can create users
def admin_create_user():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    is_admin = data.get('is_admin', False)

    if not username or not password:
        return jsonify({"message": "Username and password are required"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"message": "Username already exists"}), 409

    new_user = User(username=username, is_admin=is_admin)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "User created!", "user": new_user.to_dict()}), 201

@app.route('/api/admin/users', methods=['GET'])
@admin_required() # Only admins can view users
def admin_get_users():
    users = User.query.all()
    return jsonify([user.to_dict() for user in users])

@app.route('/api/admin/users/<int:user_id>', methods=['PUT'])
@admin_required()
def admin_update_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({"message": "User not found"}), 404

    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    is_admin = data.get('is_admin')

    if username:
        # Check if username is being changed to an existing one
        existing_user = User.query.filter(User.username == username, User.id != user_id).first()
        if existing_user:
            return jsonify({"message": "Username already exists"}), 409
        user.username = username
    if password:
        user.set_password(password)
    if is_admin is not None: # Can be true or false
        user.is_admin = is_admin

    db.session.commit()
    return jsonify({"message": "User updated!", "user": user.to_dict()}), 200

@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
@admin_required()
def admin_delete_user(user_id):
    # Prevent admin from deleting themselves
    current_user_id = int(get_jwt_identity()) # Cast to int for comparison with user_id
    if user_id == current_user_id:
        return jsonify({"message": "You cannot delete your own administrator user"}), 403

    user = User.query.get(user_id)
    if not user:
        return jsonify({"message": "User not found"}), 404

    # Delete associated locations and trips first
    Location.query.filter_by(user_id=user_id).delete()
    Trip.query.filter_by(user_id=user_id).delete()

    db.session.delete(user)
    db.session.commit()
    return jsonify({"message": "User and associated data deleted!"}), 200

# Location API
@app.route('/api/lookup-address', methods=['GET'])
def lookup_address():
    query = request.args.get('address') # Renamed 'address' to 'query'
    if not query:
        return jsonify({"message": "Address parameter (query) is missing"}), 400
    
    # Now call the modified lookup_address_nominatim which returns a list
    suggestions = lookup_address_nominatim(query)
    
    # Return the list of suggestions
    return jsonify(suggestions)

@app.route('/api/locations', methods=['POST'])
@jwt_required() # Protect this route
def create_location():
    current_user_id = get_jwt_identity()
    data = request.get_json()

    name = data.get('name')
    address = data.get('address')
    latitude = data.get('latitude')
    longitude = data.get('longitude')
    description = data.get('description')

    if not all([name, latitude is not None, longitude is not None]): # Simplified check
        return jsonify({"message": "Name, latitude, and longitude are required"}), 400

    try:
        new_location = Location(
            user_id=int(current_user_id), # Ensure user_id is int
            name=name,
            address=address,
            latitude=float(latitude),
            longitude=float(longitude),
            description=description
        )
        db.session.add(new_location)
        db.session.commit()
        return jsonify({"message": "Location created!", "location": new_location.to_dict()}), 201
    except ValueError:
        return jsonify({"message": "Invalid latitude/longitude values"}), 400
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error creating location: {e}", exc_info=True) # Log full traceback
        return jsonify({"message": f"Error creating location: {str(e)}"}), 500

@app.route('/api/locations', methods=['GET'])
@jwt_required() # Protect this route
def get_locations():
    current_user_id = get_jwt_identity()
    locations = Location.query.filter_by(user_id=int(current_user_id)).all() # Ensure user_id is int
    return jsonify([loc.to_dict() for loc in locations])


@app.route('/api/locations/<int:location_id>', methods=['PUT'])
@jwt_required()
def update_location(location_id):
    current_user_id = int(get_jwt_identity())
    location = Location.query.get(location_id)

    if not location:
        return jsonify({"message": "Location not found"}), 404

    # Ensure the user owns this location or is an admin
    if location.user_id != current_user_id:
        # Check if current user is an admin
        user = User.query.get(current_user_id)
        if not user or not user.is_admin:
            return jsonify({"message": "Unauthorized: You do not have access to this location"}), 403

    data = request.get_json()
    name = data.get('name')
    address = data.get('address')
    latitude = data.get('latitude')
    longitude = data.get('longitude')
    description = data.get('description')

    if not all([name, latitude is not None, longitude is not None]):
        return jsonify({"message": "Name, latitude, and longitude are required"}), 400

    try:
        location.name = name
        location.address = address
        location.latitude = float(latitude)
        location.longitude = float(longitude)
        location.description = description # description can be None

        db.session.commit()
        return jsonify({"message": "Location updated!", "location": location.to_dict()}), 200
    except ValueError:
        db.session.rollback()
        return jsonify({"message": "Invalid latitude/longitude values"}), 400
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error updating location: {e}", exc_info=True)
        return jsonify({"message": f"Error updating location: {str(e)}"}), 500


@app.route('/api/locations/<int:location_id>', methods=['DELETE'])
@jwt_required()
def delete_location(location_id):
    current_user_id = int(get_jwt_identity())
    location = Location.query.get(location_id)

    if not location:
        return jsonify({"message": "Location not found"}), 404

    # Ensure the user owns this location or is an admin
    if location.user_id != current_user_id:
        # Check if current user is an admin
        user = User.query.get(current_user_id)
        if not user or not user.is_admin:
            return jsonify({"message": "Unauthorized: You do not have access to this location"}), 403

    try:
        # Before deleting a location, check if it's used in any trips
        # This prevents breaking foreign key constraints
        trips_using_location = Trip.query.filter(
            (Trip.start_location_id == location_id) | (Trip.end_location_id == location_id)
        ).count()

        if trips_using_location > 0:
            return jsonify({"message": "Cannot delete location. It is used in existing trips."}), 400

        db.session.delete(location)
        db.session.commit()
        return jsonify({"message": "Location deleted!"}), 200
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error deleting location: {e}", exc_info=True)
        return jsonify({"message": f"Error deleting location: {str(e)}"}), 500

# Trips API
@app.route('/api/trips', methods=['POST'])
@jwt_required() # Protect this route
def create_trip():
    data = request.get_json()
    current_user_id = int(get_jwt_identity()) # Ensure user_id is int

    date_str = data.get('date')
    start_location_id = data.get('start_location_id')
    end_location_id = data.get('end_location_id')
    purpose = data.get('purpose')
    is_return_trip = data.get('is_return_trip', False)
    
    # NEW: Get manually entered distance from frontend payload
    manual_distance_km = data.get('distance_km') 

    if not all([date_str, start_location_id, end_location_id, purpose]):
        return jsonify(message="Missing required data for the trip"), 400

    try:
        trip_date = datetime.strptime(date_str, '%Y-%m-%d').date()
    except ValueError:
        return jsonify(message="Invalid date format. Use YYYY-MM-DD."), 400

    start_loc = Location.query.get(start_location_id)
    end_loc = Location.query.get(end_location_id)

    if not start_loc or not end_loc:
        return jsonify(message="Start or end location not found."), 404

    calculated_distance = None
    if start_loc and end_loc:
        calculated_distance = calculate_distance(
            start_loc.latitude, start_loc.longitude,
            end_loc.latitude, end_loc.longitude
        )

    # Determine the final distance for the outbound trip
    final_outbound_distance = None
    if manual_distance_km is not None and isinstance(manual_distance_km, (int, float)):
        final_outbound_distance = float(manual_distance_km) # Use manual if provided and valid
    else:
        final_outbound_distance = calculated_distance # Otherwise, use calculated

    # Create the first trip (outbound)
    new_trip = Trip(
        user_id=current_user_id,
        date=trip_date,
        start_location_id=start_location_id,
        end_location_id=end_location_id,
        purpose=purpose,
        distance_km=final_outbound_distance # Use the determined final_distance
    )
    db.session.add(new_trip)
    db.session.commit()

    # If return trip is selected, create another trip
    if is_return_trip:
        # For return trip, if a manual return distance is sent (optional, not currently in frontend)
        # You'd add `manual_return_distance_km = data.get('return_distance_km')` here if needed.
        
        return_calculated_distance = None
        if start_loc and end_loc: # Note: start and end are swapped for return
             return_calculated_distance = calculate_distance(
                end_loc.latitude, end_loc.longitude,
                start_loc.latitude, start_loc.longitude
             )
        
        # For simplicity, for the return trip, we'll just use the calculated distance
        # unless you also want a separate manual input for the return trip distance.
        final_return_distance = return_calculated_distance

        return_trip = Trip(
            user_id=current_user_id,
            date=trip_date,
            start_location_id=end_location_id, # Swapped start and end
            end_location_id=start_location_id, # Swapped start and end
            purpose=f"Return ({purpose})",
            distance_km=final_return_distance # Use the determined final_return_distance
        )
        db.session.add(return_trip)
        db.session.commit()

        return jsonify(message="Trip and return trip created", trip_id=new_trip.id, return_trip_id=return_trip.id), 201
    else:
        return jsonify(message="Trip created", trip_id=new_trip.id), 201


@app.route('/api/trips', methods=['GET'])
@jwt_required()
def get_trips():
    current_user_id = get_jwt_identity()
    user_trips = Trip.query.filter_by(user_id=int(current_user_id)).all()

    trips_data = []
    for trip in user_trips:
        trips_data.append(trip.to_dict()) # Use the to_dict method to get all trip details
    return jsonify(trips_data), 200

# NEW: Endpoint for updating and deleting a specific trip
@app.route('/api/trips/<int:trip_id>', methods=['PUT', 'DELETE'])
@jwt_required()
def trip_detail_operations(trip_id):
    current_user_id = int(get_jwt_identity())
    trip = Trip.query.get(trip_id)

    if not trip:
        return jsonify({"message": "Trip not found"}), 404

    user = User.query.get(current_user_id)
    if trip.user_id != current_user_id and (not user or not user.is_admin):
        return jsonify({"message": "Unauthorized: You do not have access to this trip"}), 403

    if request.method == 'PUT':
        data = request.get_json()
        if not data:
            return jsonify({"message": "No input data provided"}), 400

        date_str = data.get('date')
        start_location_id = data.get('start_location_id')
        end_location_id = data.get('end_location_id')
        purpose = data.get('purpose')
        
        # This part of the PUT endpoint is already correctly prioritizing manual input
        # if provided, otherwise recalculating.
        distance_km = data.get('distance_km') 

        try:
            if date_str:
                trip.date = datetime.strptime(date_str, '%Y-%m-%d').date()
            if start_location_id is not None:
                start_loc = Location.query.get(start_location_id)
                if not start_loc:
                    return jsonify({"message": "Start location not found."}), 404
                trip.start_location_id = start_location_id
                trip.start_location = start_loc

            if end_location_id is not None:
                end_loc = Location.query.get(end_location_id)
                if not end_loc:
                    return jsonify({"message": "End location not found."}), 404
                trip.end_location_id = end_location_id
                trip.end_location = end_loc
            
            if purpose is not None:
                trip.purpose = purpose
            
            if trip.start_location and trip.end_location:
                if distance_km is not None and (isinstance(distance_km, (int, float))):
                    trip.distance_km = float(distance_km)
                else:
                    trip.distance_km = calculate_distance(
                        trip.start_location.latitude, trip.start_location.longitude,
                        trip.end_location.latitude, trip.end_location.longitude
                    )
            else:
                trip.distance_km = None

            db.session.commit()
            db.session.refresh(trip)
            return jsonify({"message": "Trip updated!", "trip": trip.to_dict()}), 200
        except ValueError:
            db.session.rollback()
            return jsonify({"message": "Invalid data format (e.g., date or distance)"}), 400
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error updating trip (ID: {trip_id}): {e}", exc_info=True)
            return jsonify({"message": f"Error updating trip: {str(e)}"}), 500

    elif request.method == 'DELETE':
        try:
            db.session.delete(trip)
            db.session.commit()
            return jsonify({"message": "Trip deleted!"}), 200
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error deleting trip (ID: {trip_id}): {e}", exc_info=True)
            return jsonify({"message": f"Error deleting trip: {str(e)}"}), 500


# --- Main Run Block ---
if __name__ == '__main__':
    app.run(debug=True, port=5000)