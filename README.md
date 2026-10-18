# EcoBin AI + SmartBin 360 Dashboard

A unified smart-waste app combining the EcoBin AI and SmartBin 360 feature sets. One Python/Streamlit dashboard provides shared bin operations, fleet search and CSV export, GPS maps, route planning, demand insights, waste-classifier demos, telemetry-driven alerts, analytics, ESP32 simulation, role/settings, field tasks, and public reports.

## Run the unified Python app

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
streamlit run server.py
```

In the EcoBin-only source folder, use `streamlit run app.py`; in the combined SmartBin 360 repository, use `streamlit run server.py`. Streamlit opens at `http://localhost:8501`. Sample classifier results and demand forecasts are labeled as demonstrations, not predictions from a trained model.

## Legacy frontends

The standalone EcoBin React/Vite frontend remains available in its original repository. The original SmartBin 360 standalone `index.html` is preserved in the combined repository and can be served with `npm start`; the Streamlit dashboard is the unified app.
