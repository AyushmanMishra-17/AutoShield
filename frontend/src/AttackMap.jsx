import React from "react";
import {
  MapContainer,
  TileLayer,
  Polyline,
  CircleMarker
} from "react-leaflet";
import "leaflet/dist/leaflet.css";

const TARGET = [28.6, 77.2]; // India

export default function AttackMap({ alerts }) {
  return (
    <div style={{ height: "400px", marginTop: "20px" }}>
      <MapContainer
        center={[20, 0]}
        zoom={2}
        style={{ height: "100%", width: "100%" }}
        scrollWheelZoom={false}
      >
        {/* 🌍 Real Map */}
        <TileLayer
          attribution="&copy; OpenStreetMap"
          url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
        />

        {/* 🔴 Attack Lines */}
        {alerts.map((a, i) => (
          <Polyline
            key={i}
            positions={[
              [a.lat || 0, a.lon || 0],
              TARGET
            ]}
            pathOptions={{
              color: "red",
              weight: 2,
              opacity: 0.7
            }}
          />
        ))}

        {/* 🔴 Attack Origins */}
        {alerts.map((a, i) => (
          <CircleMarker
            key={`marker-${i}`}
            center={[a.lat || 0, a.lon || 0]}
            radius={4}
            pathOptions={{
              color: "red",
              fillColor: "red",
              fillOpacity: 0.8
            }}
          />
        ))}

        {/* 🟢 Server */}
        <CircleMarker
          center={TARGET}
          radius={6}
          pathOptions={{
            color: "#00ff88",
            fillColor: "#00ff88",
            fillOpacity: 1
          }}
        />
      </MapContainer>
    </div>
  );
}