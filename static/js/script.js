//  Client-side JavaScript for Nakuru Safety Platform

function getLocation() {
    if (navigator.geolocation) {
        navigator.geolocation.getCurrentPosition(showPosition, showError);
    } else {
        document.getElementById("locationStatus").innerHTML =
            '<div class="alert alert-warning">Geolocation not supported. Using default Nakuru location.</div>';
    }
}

function showPosition(position) {
    document.getElementById("lat").value = position.coords.latitude;
    document.getElementById("lon").value = position.coords.longitude;
    document.getElementById("locationStatus").innerHTML =
        '<div class="alert alert-success">GPS location captured successfully!</div>';
}

function showError(error) {
    // Default to Nakuru Town center
    document.getElementById("lat").value = -0.3031;
    document.getElementById("lon").value = 36.0800;

    let message = '';
    switch(error.code) {
        case error.PERMISSION_DENIED:
            message = "Location access denied. Using default Nakuru location.";
            break;
        case error.POSITION_UNAVAILABLE:
            message = "Location unavailable. Using default Nakuru location.";
            break;
        case error.TIMEOUT:
            message = "Location request timed out. Using default Nakuru location.";
            break;
        default:
            message = "Location error. Using default Nakuru location.";
    }

    document.getElementById("locationStatus").innerHTML =
        '<div class="alert alert-info">' + message + '</div>';
}

// Form submission handler
document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('incidentForm');

    if (form) {
        form.addEventListener('submit', function(e) {
            e.preventDefault();

            const formData = new FormData(form);

            // Show loading state
            const submitBtn = form.querySelector('button[type="submit"]');
            const originalText = submitBtn.innerHTML;
            submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Submitting...';
            submitBtn.disabled = true;

            fetch('/report', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    // Success message
                    alert('✓ ' + data.success);
                    form.reset();
                    document.getElementById('locationStatus').innerHTML = '';

                    // Redirect to home after 2 seconds
                    setTimeout(() => {
                        window.location.href = '/';
                    }, 2000);
                } else if (data.error) {
                    alert('✗ Error: ' + data.error);
                    submitBtn.innerHTML = originalText;
                    submitBtn.disabled = false;
                }
            })
            .catch(error => {
                alert('✗ Error submitting report. Please try again.');
                console.error('Error:', error);
                submitBtn.innerHTML = originalText;
                submitBtn.disabled = false;
            });
        });
    }
});

// File upload preview
document.addEventListener('DOMContentLoaded', function() {
    const mediaInput = document.getElementById('media');

    if (mediaInput) {
        mediaInput.addEventListener('change', function() {
            const file = this.files[0];
            if (file) {
                const fileSize = (file.size / 1024 / 1024).toFixed(2); // MB
                const fileType = file.type;

                if (fileSize > 10) {
                    alert('File size exceeds 10MB limit. Please choose a smaller file.');
                    this.value = '';
                    return;
                }

                console.log('File selected:', file.name, fileSize + 'MB');
            }
        });
    }
});
