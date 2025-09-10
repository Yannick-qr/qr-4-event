async function loadGoogleMaps() {
  const res = await fetch("/api/config/maps-key");
  const data = await res.json();
  if (!data.key) {
    console.error("❌ Clé Google Maps manquante");
    return;
  }

  const script = document.createElement("script");
  script.src = `https://maps.googleapis.com/maps/api/js?key=${data.key}&libraries=places`;
  script.async = true;
  script.defer = true;
  script.onload = () => initAutocomplete(); // Quand Google est prêt
  document.head.appendChild(script);
}

function initAutocomplete() {
  // Fonction générique avec affichage carte
  function setupAutocomplete(inputId, latId, lngId, mapId) {
    const input = document.getElementById(inputId);
    if (!input) return;

  const autocomplete = new google.maps.places.Autocomplete(input, {
  // pas de restriction types → adresses + lieux
  });
  autocomplete.setFields(["geometry", "name", "formatted_address", "place_id"]);


    const mapContainer = document.getElementById(mapId);
    let map, marker;

    // ⚡ Si on a déjà des coordonnées (cas édition), afficher directement la carte
    const latField = document.getElementById(latId);
    const lngField = document.getElementById(lngId);
    if (latField && lngField && latField.value && lngField.value) {
      const lat = parseFloat(latField.value);
      const lng = parseFloat(lngField.value);
      if (!isNaN(lat) && !isNaN(lng) && mapContainer) {
        map = new google.maps.Map(mapContainer, {
          center: { lat, lng },
          zoom: 15
        });
        marker = new google.maps.Marker({
          position: { lat, lng },
          map: map
        });
        mapContainer.style.display = "block";
      }
    }

    // Quand un lieu est choisi
    autocomplete.addListener("place_changed", () => {
      const place = autocomplete.getPlace();
      if (place.geometry) {
        const lat = place.geometry.location.lat();
        const lng = place.geometry.location.lng();

        console.log(`📍 Lieu choisi (${inputId}):`, place);

        if (latField && lngField) {
          latField.value = lat;
          lngField.value = lng;
        }

        if (mapContainer) {
          if (!map) {
            map = new google.maps.Map(mapContainer, {
              center: { lat, lng },
              zoom: 15
            });
            marker = new google.maps.Marker({
              position: { lat, lng },
              map: map
            });
          } else {
            map.setCenter({ lat, lng });
            marker.setPosition({ lat, lng });
          }
          mapContainer.style.display = "block";
        }
      }
    });
  }

  // 🔹 Autocomplete sur création
  setupAutocomplete("location", "latitude", "longitude", "mapPreview");

  // 🔹 Autocomplete sur édition
  setupAutocomplete("edit_location", "edit_latitude", "edit_longitude", "editMapPreview");
}

// Charger Google Maps au démarrage
loadGoogleMaps();
