/**
 * Geolocation Utility - Auto-detect user location from browser
 */

class GeolocationDetector {
    constructor() {
        this.locationName = null;
        this.coordinates = null;
    }

    /**
     * Detect user location using browser Geolocation API
     */
    async detectLocation() {
        return new Promise((resolve, reject) => {
            if (!navigator.geolocation) {
                reject(new Error('Geolocation is not supported by your browser'));
                return;
            }

            const options = {
                enableHighAccuracy: true,
                timeout: 10000,
                maximumAge: 0 // Force fresh location
            };

            navigator.geolocation.getCurrentPosition(
                async (position) => {
                    this.coordinates = {
                        latitude: position.coords.latitude,
                        longitude: position.coords.longitude,
                        accuracy: position.coords.accuracy
                    };

                    try {
                        // Reverse geocode to get location name
                        const locationName = await this.reverseGeocode(
                            this.coordinates.latitude,
                            this.coordinates.longitude
                        );
                        this.locationName = locationName;
                        resolve(locationName);
                    } catch (error) {
                        console.warn('Reverse geocoding failed:', error);
                        // Fallback to coordinates
                        this.locationName = `${this.coordinates.latitude.toFixed(4)}, ${this.coordinates.longitude.toFixed(4)}`;
                        resolve(this.locationName);
                    }
                },
                (error) => {
                    let errorMsg = 'Location detection failed: ';
                    switch (error.code) {
                        case error.PERMISSION_DENIED:
                            errorMsg += 'Permission denied. Please enable location access.';
                            break;
                        case error.POSITION_UNAVAILABLE:
                            errorMsg += 'Location information unavailable.';
                            break;
                        case error.TIMEOUT:
                            errorMsg += 'Location request timed out.';
                            break;
                        default:
                            errorMsg += 'Unknown error occurred.';
                            break;
                    }
                    reject(new Error(errorMsg));
                },
                options
            );
        });
    }

    /**
     * Reverse geocode coordinates to location name
     * Uses OpenStreetMap Nominatim API (free, no API key required)
     */
    async reverseGeocode(latitude, longitude) {
        try {
            // Use OpenStreetMap Nominatim for reverse geocoding
            const url = `https://nominatim.openstreetmap.org/reverse?format=json&lat=${latitude}&lon=${longitude}&zoom=10&addressdetails=1`;
            
            const response = await fetch(url, {
                headers: {
                    'User-Agent': 'HashCatMaskGenerator/1.0' // Required by Nominatim
                }
            });

            if (!response.ok) {
                throw new Error('Geocoding service unavailable');
            }

            const data = await response.json();
            
            // Extract location name from response
            if (data.address) {
                // Try to get city/town name
                const city = data.address.city || 
                           data.address.town || 
                           data.address.village || 
                           data.address.municipality ||
                           data.address.county;
                
                const state = data.address.state || 
                            data.address.region || 
                            data.address.province;
                
                // Construct location string
                if (city && state) {
                    return `${city}, ${state}`;
                } else if (city) {
                    return city;
                } else if (state) {
                    return state;
                } else if (data.display_name) {
                    // Fallback to display name
                    const parts = data.display_name.split(',');
                    return parts.slice(0, 2).join(', ').trim();
                }
            }
            
            // Ultimate fallback
            return data.display_name?.split(',')[0] || 'Unknown Location';
            
        } catch (error) {
            console.error('Reverse geocoding error:', error);
            // Fallback to coordinates-based name
            return `${latitude.toFixed(4)}, ${longitude.toFixed(4)}`;
        }
    }

    /**
     * Get a simplified location name (just city)
     */
    getCityName() {
        if (!this.locationName) return null;
        
        // Extract city from "City, State" format
        const parts = this.locationName.split(',');
        return parts[0].trim();
    }

    /**
     * Check if geolocation is available
     */
    static isAvailable() {
        return 'geolocation' in navigator;
    }
}

// Export for use in other modules
window.GeolocationDetector = GeolocationDetector;
