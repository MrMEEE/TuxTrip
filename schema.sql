DROP TABLE IF EXISTS trips;
DROP TABLE IF EXISTS locations;

CREATE TABLE locations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    address TEXT,
    latitude REAL,           -- Added latitude
    longitude REAL,          -- Added longitude
    description TEXT
);

CREATE TABLE trips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    date TEXT NOT NULL,
    start_time TEXT,
    end_time TEXT,
    start_location_id INTEGER NOT NULL,
    end_location_id INTEGER NOT NULL,
    purpose TEXT NOT NULL,
    notes TEXT,
    trip_type TEXT NOT NULL DEFAULT 'Business',
    odometer_start INTEGER,
    odometer_end INTEGER,
    calculated_distance_meters REAL, -- New column to store calculated distance in meters
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (start_location_id) REFERENCES locations(id),
    FOREIGN KEY (end_location_id) REFERENCES locations(id)
);