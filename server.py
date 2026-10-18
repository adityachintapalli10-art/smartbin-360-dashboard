import random

import auth
import pandas as pd
import streamlit as st


st.set_page_config(page_title="EcoBin AI + SmartBin 360", page_icon="♻️", layout="wide")
auth.initialize_auth()
user = auth.current_user()
if user is None:
    auth.render_authentication()
    st.stop()
auth.render_authenticated_sidebar(user)


def enforce_permission(permission: str) -> None:
    auth.require_permission(user, permission)


INITIAL_BINS = [
    {"id": "BIN-042", "name": "MBU Campus Quad", "area": "MBU Campus Zone", "lat": 13.6288, "lon": 79.4192, "fill": 92, "battery": 45, "odor": 185, "temp": 34, "waste": "Plastic & Wet Waste", "lock": "Locked", "worker": "Ramesh Kumar", "cleaned": "18 hrs ago"},
    {"id": "BIN-018", "name": "Central Bus Stand Gate 1", "area": "Tirupati Town", "lat": 13.6320, "lon": 79.4230, "fill": 68, "battery": 28, "odor": 110, "temp": 30, "waste": "Paper & Organic", "lock": "Unlocked", "worker": "Srinivas V.", "cleaned": "5 hrs ago"},
    {"id": "BIN-007", "name": "SV University Road", "area": "Tirupati Town", "lat": 13.6220, "lon": 79.4080, "fill": 24, "battery": 94, "odor": 35, "temp": 28, "waste": "Dry Trash", "lock": "Locked", "worker": "Unassigned", "cleaned": "1 hr ago"},
    {"id": "BIN-011", "name": "Railway Station Platform 1", "area": "Tirupati Town", "lat": 13.6260, "lon": 79.4150, "fill": 88, "battery": 80, "odor": 210, "temp": 33, "waste": "Food & Wet Waste", "lock": "Locked", "worker": "K. Venkatesh", "cleaned": "14 hrs ago"},
    {"id": "BIN-025", "name": "Alipiri Checkpoint", "area": "Alipiri Circle", "lat": 13.6500, "lon": 79.4000, "fill": 45, "battery": 88, "odor": 50, "temp": 27, "waste": "Plastic & Bottles", "lock": "Unlocked", "worker": "Unassigned", "cleaned": "3 hrs ago"},
    {"id": "BIN-033", "name": "Kapila Theertham Entrance", "area": "Alipiri Circle", "lat": 13.6420, "lon": 79.4100, "fill": 82, "battery": 72, "odor": 140, "temp": 31, "waste": "E-Waste & Metals", "lock": "Locked", "worker": "Anil Reddy", "cleaned": "12 hrs ago"},
    {"id": "BIN-101", "name": "Central Library Quad", "area": "MBU Campus Zone", "lat": 13.6288, "lon": 79.4192, "fill": 88, "battery": 92, "odor": 72, "temp": 29, "waste": "Recyclable", "lock": "Locked", "worker": "Rajesh Kumar", "cleaned": "2 mins ago"},
    {"id": "BIN-102", "name": "Engineering Block A", "area": "MBU Campus Zone", "lat": 13.6302, "lon": 79.4180, "fill": 97, "battery": 84, "odor": 120, "temp": 32, "waste": "Dry Waste", "lock": "Locked", "worker": "Rajesh Kumar", "cleaned": "Just now"},
    {"id": "BIN-103", "name": "Student Cafeteria South", "area": "MBU Campus Zone", "lat": 13.6275, "lon": 79.4210, "fill": 42, "battery": 99, "odor": 68, "temp": 28, "waste": "Wet Waste", "lock": "Unlocked", "worker": "Unassigned", "cleaned": "5 mins ago"},
    {"id": "BIN-104", "name": "Science Auditorium Lobby", "area": "MBU Campus Zone", "lat": 13.6315, "lon": 79.4225, "fill": 65, "battery": 91, "odor": 84, "temp": 29, "waste": "Recyclable", "lock": "Locked", "worker": "K. Venkatesh", "cleaned": "12 mins ago"},
    {"id": "BIN-105", "name": "Hostel Block 3 Gate", "area": "MBU Campus Zone", "lat": 13.6260, "lon": 79.4170, "fill": 99, "battery": 76, "odor": 225, "temp": 35, "waste": "Hazardous", "lock": "Locked", "worker": "Anil Reddy", "cleaned": "1 min ago"},
    {"id": "BIN-106", "name": "Sports Stadium Entrance", "area": "MBU Campus Zone", "lat": 13.6330, "lon": 79.4200, "fill": 22, "battery": 100, "odor": 35, "temp": 27, "waste": "Dry Waste", "lock": "Unlocked", "worker": "Unassigned", "cleaned": "15 mins ago"},
    {"id": "BIN-107", "name": "Admin Building Porch", "area": "MBU Campus Zone", "lat": 13.6295, "lon": 79.4165, "fill": 54, "battery": 95, "odor": 52, "temp": 28, "waste": "Recyclable", "lock": "Locked", "worker": "Srinivas V.", "cleaned": "8 mins ago"},
    {"id": "BIN-108", "name": "Medical Center West", "area": "MBU Campus Zone", "lat": 13.6250, "lon": 79.4190, "fill": 91, "battery": 88, "odor": 160, "temp": 31, "waste": "Hazardous", "lock": "Locked", "worker": "Ramesh Kumar", "cleaned": "3 mins ago"},
    {"id": "BIN-109", "name": "Computer Science Lab", "area": "MBU Campus Zone", "lat": 13.6310, "lon": 79.4185, "fill": 34, "battery": 96, "odor": 30, "temp": 27, "waste": "Dry Waste", "lock": "Unlocked", "worker": "Unassigned", "cleaned": "20 mins ago"},
    {"id": "BIN-110", "name": "Campus Main Gate", "area": "MBU Campus Zone", "lat": 13.6270, "lon": 79.4150, "fill": 78, "battery": 90, "odor": 89, "temp": 30, "waste": "Recyclable", "lock": "Locked", "worker": "K. Venkatesh", "cleaned": "6 mins ago"},
    {"id": "BIN-111", "name": "Architecture Studio", "area": "MBU Campus Zone", "lat": 13.6322, "lon": 79.4215, "fill": 12, "battery": 98, "odor": 22, "temp": 27, "waste": "Wet Waste", "lock": "Unlocked", "worker": "Unassigned", "cleaned": "25 mins ago"},
    {"id": "BIN-112", "name": "Business School Atrium", "area": "MBU Campus Zone", "lat": 13.6280, "lon": 79.4230, "fill": 96, "battery": 82, "odor": 130, "temp": 32, "waste": "Dry Waste", "lock": "Locked", "worker": "Rajesh Kumar", "cleaned": "Just now"},
]

TASKS = [
    {"Task": "TSK-101", "Bin": "BIN-042", "Area": "MBU Campus Quad", "Priority": "Urgent", "Status": "Assigned", "Worker": "Ramesh Kumar", "ETA": "15 mins"},
    {"Task": "TSK-102", "Bin": "BIN-011", "Area": "Railway Station", "Priority": "Urgent", "Status": "In-Progress", "Worker": "K. Venkatesh", "ETA": "8 mins"},
    {"Task": "TSK-103", "Bin": "BIN-033", "Area": "Kapila Theertham", "Priority": "High", "Status": "Pending", "Worker": "Anil Reddy", "ETA": "35 mins"},
    {"Task": "TSK-104", "Bin": "BIN-018", "Area": "Central Bus Stand", "Priority": "Medium", "Status": "Completed", "Worker": "Srinivas V.", "ETA": "Done"},
]

if "bins" not in st.session_state:
    st.session_state.bins = [dict(bin_data) for bin_data in INITIAL_BINS]
if "reports" not in st.session_state:
    st.session_state.reports = [
        {"Report": "CMP-801", "Bin": "BIN-042", "Issue": "Overflowing wet waste onto walkway", "Reported by": "Ananya S.", "Time": "25m ago", "Status": "In Review"},
        {"Report": "CMP-802", "Bin": "BIN-018", "Issue": "Odor issue near bus waiting bench", "Reported by": "Vikram R.", "Time": "1h ago", "Status": "Resolved"},
        {"Report": "CMP-803", "Bin": "BIN-011", "Issue": "Solar panel blocked by overhead banner", "Reported by": "Karthik M.", "Time": "3h ago", "Status": "Pending"},
    ]
if "resolved_alerts" not in st.session_state:
    st.session_state.resolved_alerts = set()
if "classification_result" not in st.session_state:
    st.session_state.classification_result = None
if "completed_tasks" not in st.session_state:
    st.session_state.completed_tasks = set()
if "toast" in st.session_state:
    st.toast(st.session_state.pop("toast"))

st.markdown(
    """
    <style>
    .stApp { background: #070b12; color: #e2e8f0; }
    [data-testid="stMetric"] { background: #0d1627; border: 1px solid #1e293b; padding: 14px; border-radius: 12px; }
    [data-testid="stSidebar"] { background: #0b1322; }
    h1, h2, h3 { color: #f1f5f9; }
    </style>
    """,
    unsafe_allow_html=True,
)

st.title("♻️ EcoBin AI + SmartBin 360")
st.caption("UNIFIED SMART WASTE DASHBOARD · LIVE FLEET + IOT TELEMETRY")

with st.sidebar:
    st.header("Control center")
    region = st.selectbox("Active region", ["All", "Tirupati Town", "MBU Campus Zone", "Alipiri Circle"])
    role = user["role"]
    st.caption(f'{user["full_name"]} · {user["designation"]} · {role.title()}')
    st.page_link(
        "https://github.com/adityachintapalli10-art/smartbin-360",
        label="SmartBin 360 repository",
        icon=":material/open_in_new:",
    )
    st.divider()
    st.caption("IoT fleet grid")
    st.progress(1.0, text="100% online")
    if auth.has_permission(user, "manage_bins"):
        with st.expander("Register a smart bin"):
            new_id = st.text_input("Bin serial code", placeholder="BIN-099")
            new_area = st.selectbox("Region / zone", ["MBU Campus Zone", "Tirupati Town", "Alipiri Circle"])
            if st.button("Pair & register", width="stretch"):
                enforce_permission("manage_bins")
                numeric_ids = [
                    int(item["id"][4:])
                    for item in st.session_state.bins
                    if item["id"].startswith("BIN-") and item["id"][4:].isdigit()
                ]
                bin_id = new_id.strip().upper() or f"BIN-{max(numeric_ids, default=0) + 1:03}"
                if any(item["id"] == bin_id for item in st.session_state.bins):
                    st.error(f"{bin_id} already exists.")
                else:
                    st.session_state.bins.append({
                        "id": bin_id, "name": f"{bin_id} ({new_area})", "area": new_area,
                        "lat": 13.629, "lon": 79.418, "fill": 10, "battery": 99, "odor": 18,
                        "temp": 27, "waste": "Dry & Recyclables", "lock": "Locked",
                        "worker": "Unassigned", "cleaned": "Just now",
                    })
                    st.session_state.toast = f"{bin_id} successfully paired."
                    st.rerun()

bins = st.session_state.bins
visible_bins = [item for item in bins if region == "All" or item["area"] == region]
if not visible_bins:
    st.info("No bins are registered in this region yet.")
    st.stop()

selected_id = st.selectbox("Focused bin", [item["id"] for item in visible_bins], label_visibility="collapsed")
selected = next(item for item in bins if item["id"] == selected_id)
alerts = sum(item["fill"] >= 80 for item in bins)
avg_fill = round(sum(item["fill"] for item in bins) / len(bins))
avg_battery = round(sum(item["battery"] for item in bins) / len(bins))

tab_definitions = [
    ("smartbin360", "SmartBin 360", "dashboard"),
    ("overview", "Overview", "dashboard"),
    ("map", "GIS live map", "map"),
    ("fleet", "Dustbin fleet", "fleet"),
    ("routes", "Collection routes", "routes"),
    ("forecast", "AI demand", "forecast"),
    ("classifier", "Waste classifier", "classifier"),
    ("alerts", "Alerts center", "alerts"),
    ("analytics", "Analytics & CO₂", "analytics"),
    ("telemetry", "ESP32 simulator", "telemetry"),
    ("tasks", "Field staff tasks", "tasks"),
    ("reports", "Public reports", "reports"),
    ("admin", "RBAC & settings", "user_admin"),
]
visible_tabs = [item for item in tab_definitions if auth.has_permission(user, item[2])]
section_tabs = {
    key: tab
    for (key, _, _), tab in zip(
        visible_tabs,
        st.tabs([label for _, label, _ in visible_tabs]),
    )
}

if "smartbin360" in section_tabs:
    with section_tabs["smartbin360"]:
        st.subheader("SmartBin 360 operations")
        st.caption("Quick view of the connected SmartBin fleet and its operational status.")
        smartbin_cols = st.columns(4)
        smartbin_cols[0].metric("Connected bins", len(bins))
        smartbin_cols[1].metric("Needs collection", sum(item["fill"] >= 80 for item in bins))
        smartbin_cols[2].metric("Average solar battery", f"{avg_battery}%")
        smartbin_cols[3].metric(
            "Sensor alerts",
            sum(item["odor"] >= 150 or item["battery"] < 30 for item in bins),
        )
        st.markdown("#### Fleet status")
        st.dataframe(
            [
                {
                    "Bin": item["id"],
                    "Location": item["name"],
                    "Area": item["area"],
                    "Fill": f'{item["fill"]}%',
                    "Battery": f'{item["battery"]}%',
                    "Status": "Collection needed" if item["fill"] >= 80 else "Online",
                }
                for item in visible_bins
            ],
            hide_index=True,
            width="stretch",
        )
        st.page_link(
            "https://github.com/adityachintapalli10-art/smartbin-360",
            label="Open the SmartBin 360 source repository",
            icon=":material/open_in_new:",
        )

if "overview" in section_tabs:
    with section_tabs["overview"]:
        metric_cols = st.columns(4)
        metric_cols[0].metric("Critical alerts (>80%)", f"{alerts} bins", delta="Action needed", delta_color="inverse")
        metric_cols[1].metric("Average capacity fill", f"{avg_fill}%", f"{len(bins)} connected bins")
        metric_cols[2].metric("Solar grid battery", f"{avg_battery}%", "Dual solar charging")
        metric_cols[3].metric("CO₂ saved this month", "890 kg", "AI route optimization")

        left, center, right = st.columns([1, 1.35, 1])
        with left:
            st.subheader("Monitored bins")
            st.dataframe(
                [{"Bin": b["id"], "Location": b["name"], "Fill": f'{b["fill"]}%', "Lock": b["lock"]} for b in visible_bins],
                hide_index=True,
                width="stretch",
            )
            st.subheader("Bin locations")
            st.map(pd.DataFrame([{"lat": b["lat"], "lon": b["lon"]} for b in visible_bins]), size=100)
        with center:
            st.subheader(f"Active bin · {selected['id']}")
            st.write(selected["name"], "·", selected["area"])
            st.progress(selected["fill"] / 100, text=f"Fill level · {selected['fill']}%")
            gauge_cols = st.columns(3)
            gauge_cols[0].metric("Battery", f'{selected["battery"]}%')
            gauge_cols[1].metric("Odor / gas", f'{selected["odor"]} PPM')
            gauge_cols[2].metric("Temperature", f'{selected["temp"]}°C')
            action_cols = st.columns(2)
            if auth.has_permission(user, "collect_bins") and action_cols[0].button("Mark as cleaned", width="stretch"):
                enforce_permission("collect_bins")
                selected.update(fill=5, odor=15, cleaned="Just now")
                st.session_state.toast = f'{selected["id"]} marked as cleaned.'
                st.rerun()
            if auth.has_permission(user, "control_hardware") and action_cols[1].button(f'{selected["lock"]} · toggle lock', width="stretch"):
                enforce_permission("control_hardware")
                selected["lock"] = "Unlocked" if selected["lock"] == "Locked" else "Locked"
                st.session_state.toast = f'{selected["id"]} lid is {selected["lock"].lower()}.'
                st.rerun()
            if auth.has_permission(user, "simulate_telemetry"):
                st.subheader("Live sensor simulator")
                selected["fill"] = st.slider("Fill level (%)", 0, 100, selected["fill"])
                selected["battery"] = st.slider("Battery (%)", 0, 100, selected["battery"])
                selected["odor"] = st.slider("Gas / odor (PPM)", 10, 300, selected["odor"])
                if st.button("Simulate sensor reading"):
                    enforce_permission("simulate_telemetry")
                    selected["fill"] = max(5, min(100, selected["fill"] + random.choice([-2, -1, 1, 2])))
                    selected["odor"] = max(10, min(300, selected["odor"] + random.choice([-4, -2, 2, 4])))
                    st.rerun()
        with right:
            st.subheader("AI overflow forecast")
            forecast = pd.DataFrame(
                {"Actual": [15, 35, 62, 78, selected["fill"], 95], "Predicted": [18, 38, 60, 75, 89, 94]},
                index=["06:00", "09:00", "12:00", "15:00", "18:00", "21:00"],
            )
            st.line_chart(forecast, y=["Actual", "Predicted"], color=["#f59e0b", "#34d399"])
            st.subheader("Staff roster")
            st.dataframe(pd.DataFrame(TASKS[:3])[["Worker", "Bin", "Status", "ETA"]], hide_index=True, width="stretch")
            if auth.has_permission(user, "dispatch") and st.button("Send emergency dispatch", width="stretch"):
                enforce_permission("dispatch")
                st.toast("Dispatch alert sent to collection drivers.")

        with st.expander("Smart solar bin hardware showcase"):
            st.markdown(
                "**Solar lid:** 12V 20W monocrystalline · **Fill sensors:** dual HC-SR04 · "
                "**AI camera:** ESP32-CAM edge classifier · **Air quality:** MQ-135 · "
                "**Lid:** 12V electromagnetic lock · **Power:** LiFePO₄ battery"
            )

if "map" in section_tabs:
    with section_tabs["map"]:
        st.subheader("Municipal GIS mapping & GPS fleet grid")
        st.caption("Live fill-level status for registered bins in the selected area.")
        map_search = st.text_input("Search map by bin, location, or waste category", key="map_search").casefold()
        map_status = st.selectbox(
            "Show fill status",
            ["All statuses", "Critical (95–100%)", "High (80–94%)", "Medium (50–79%)", "Normal (0–49%)"],
            key="map_status",
        )
        map_bins = [b for b in visible_bins if map_search in f'{b["id"]} {b["name"]} {b["waste"]}'.casefold()]
        status_ranges = {
            "Critical (95–100%)": lambda fill: fill >= 95,
            "High (80–94%)": lambda fill: 80 <= fill < 95,
            "Medium (50–79%)": lambda fill: 50 <= fill < 80,
            "Normal (0–49%)": lambda fill: fill < 50,
        }
        if map_status in status_ranges:
            map_bins = [b for b in map_bins if status_ranges[map_status](b["fill"])]
        if map_bins:
            st.map(pd.DataFrame([{"lat": b["lat"], "lon": b["lon"], "fill": b["fill"]} for b in map_bins]), size=150, color="#10b981")
        else:
            st.info("No bins match the map filters.")
        st.dataframe(pd.DataFrame(map_bins)[["id", "name", "area", "fill", "battery", "odor", "waste", "lock"]], hide_index=True, width="stretch")

if "fleet" in section_tabs:
    with section_tabs["fleet"]:
        st.subheader("SmartBin 360 · Dustbin fleet management")
        st.caption("Search the merged fleet, filter by waste category, inspect telemetry, and export a CSV report.")
        fleet_search = st.text_input("Search bin ID, location, category, or area", key="fleet_search").casefold()
        categories = ["All categories"] + sorted({b["waste"] for b in bins})
        fleet_category = st.selectbox("Waste category", categories)
        fleet_bins = [
            b for b in bins
            if fleet_search in f'{b["id"]} {b["name"]} {b["waste"]} {b["area"]}'.casefold()
            and (fleet_category == "All categories" or b["waste"] == fleet_category)
        ]
        fleet_frame = pd.DataFrame([
            {
                "Bin ID": b["id"], "Location": b["name"], "Area": b["area"], "Waste category": b["waste"],
                "Fill (%)": b["fill"], "Solar battery (%)": b["battery"], "Odor (PPM)": b["odor"],
                "Last cleaned": b["cleaned"], "Status": "Critical" if b["fill"] >= 95 else "High" if b["fill"] >= 80 else "Warning" if b["fill"] >= 50 else "Normal",
            } for b in fleet_bins
        ])
        st.dataframe(fleet_frame, hide_index=True, width="stretch")
        st.download_button(
            "Export filtered fleet CSV",
            data=fleet_frame.to_csv(index=False).encode("utf-8"),
            file_name="smartbin-fleet-report.csv",
            mime="text/csv",
            disabled=fleet_frame.empty,
        )
        if auth.has_permission(user, "manage_bins"):
            with st.expander("Register a bin with GPS coordinates and waste category"):
                with st.form("fleet_add_bin"):
                    add_cols = st.columns(2)
                    add_id = add_cols[0].text_input("Bin serial code", placeholder="BIN-120")
                    add_name = add_cols[1].text_input("Location", placeholder="Campus location")
                    add_area = add_cols[0].selectbox("Area", ["MBU Campus Zone", "Tirupati Town", "Alipiri Circle"], key="fleet_add_area")
                    add_waste = add_cols[1].selectbox("Waste category", ["Wet Waste", "Dry Waste", "Recyclable", "Hazardous", "Organic & Food", "E-Waste & Metals"])
                    add_lat, add_lon = st.columns(2)
                    lat = add_lat.number_input("Latitude", value=13.6288, format="%.6f")
                    lon = add_lon.number_input("Longitude", value=79.4192, format="%.6f")
                    add_submitted = st.form_submit_button("Register smart bin")
                if add_submitted:
                    enforce_permission("manage_bins")
                    bin_id = add_id.strip().upper()
                    if not bin_id or not add_name.strip():
                        st.error("Enter a bin serial code and location.")
                    elif any(item["id"] == bin_id for item in bins):
                        st.error(f"{bin_id} already exists.")
                    else:
                        bins.append({
                            "id": bin_id, "name": add_name.strip(), "area": add_area, "lat": lat, "lon": lon,
                            "fill": 10, "battery": 100, "odor": 18, "temp": 27, "waste": add_waste,
                            "lock": "Locked", "worker": "Unassigned", "cleaned": "Just now",
                        })
                        st.session_state.toast = f"{bin_id} registered successfully."
                        st.rerun()

if "routes" in section_tabs:
    with section_tabs["routes"]:
        st.subheader("AI dynamic route optimization")
        st.caption("Prioritizes bins at or above 80% capacity.")
        urgent_bins = sorted((b for b in bins if b["fill"] >= 50), key=lambda b: b["fill"], reverse=True)
        route_cols = st.columns(4)
        route_cols[0].metric("Priority bins", f"{alerts}")
        route_cols[1].metric("Route distance", "12.4 km", "3.8 km saved")
        route_cols[2].metric("Estimated fuel", "2.1 L")
        route_cols[3].metric("Collection time", "35 mins")
        if st.button("Recalculate optimal route"):
            st.toast("Optimized route generated · 3.8 km and 22 minutes saved.")
        st.dataframe(
            pd.DataFrame([{"Stop": i, "Bin": b["id"], "Location": b["name"], "Fill": f'{b["fill"]}%', "Waste": b["waste"], "ETA": f"{10 + i * 8} mins"} for i, b in enumerate(urgent_bins, 1)]),
            hide_index=True,
            width="stretch",
        )
        if auth.has_permission(user, "dispatch") and st.button("Dispatch Truck Alpha"):
            enforce_permission("dispatch")
            st.toast("Truck Alpha dispatched along the optimized collection route.")

if "forecast" in section_tabs:
    with section_tabs["forecast"]:
        st.subheader("AI fill-level prediction & demand forecasting")
        st.caption("Sample forecast based on the source dashboard's demand history; this is a demo, not a trained model.")
        forecast_cols = st.columns([2, 1])
        with forecast_cols[0]:
            demand = pd.DataFrame(
                {"Predicted waste volume (kg)": [420, 380, 510, 590, 720, 840, 690]},
                index=["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
            )
            st.line_chart(demand, color="#10b981")
        with forecast_cols[1]:
            st.markdown("#### Early warnings & insights")
            st.warning("Cafeteria demand: sample history predicts a Friday lunch wet-waste surge. Consider a pre-dispatch.")
            st.info("Hostel Block 3: BIN-105 is near capacity. Increase collection frequency during weekends.")
            st.success(f"Fleet solar battery average is {avg_battery}%. {sum(b['battery'] < 30 for b in bins)} bin(s) need a battery check.")

if "classifier" in section_tabs:
    with section_tabs["classifier"]:
        st.subheader("AI waste classification & sustainability scanner")
        st.caption("Sample classifications are simulated demonstrations, not a trained computer-vision model.")
        sample_items = [
            ("Plastic Bottle", "Recyclable", 98.4, "🥤"),
            ("Banana Peel", "Wet Waste", 95.1, "🍌"),
            ("Used Battery", "Hazardous", 99.2, "🔋"),
            ("Cardboard Box", "Dry Waste", 96.8, "📦"),
        ]
        sample_cols = st.columns(4)
        for col, (item, category, confidence, emoji) in zip(sample_cols, sample_items):
            if col.button(f"{emoji} {item}", key=f"classify_{item}", width="stretch"):
                st.session_state.classification_result = {
                    "item": item, "category": category, "confidence": confidence,
                    "source": "Sample demonstration",
                }
        upload_col, result_col = st.columns(2)
        with upload_col:
            uploaded_image = st.file_uploader("Upload a waste image", type=["png", "jpg", "jpeg", "webp"])
            if uploaded_image:
                st.image(uploaded_image, caption="Uploaded image · choose a category to save a demo label", width="stretch")
                chosen_category = st.selectbox("Demo category", ["Wet Waste", "Dry Waste", "Recyclable", "Hazardous"], key="uploaded_category")
                if st.button("Save demo classification"):
                    st.session_state.classification_result = {
                        "item": uploaded_image.name, "category": chosen_category,
                        "confidence": None, "source": "User-selected demo label",
                    }
        with result_col:
            st.markdown("#### Classification result")
            if st.session_state.classification_result:
                result = st.session_state.classification_result
                st.success(f'{result["category"]}: {result["item"]}')
                if result["confidence"] is not None:
                    st.metric("Sample confidence", f'{result["confidence"]}%')
                st.caption(result["source"])
                st.info(f'Recommended disposal: use the nearest {result["category"]} bin.')
            else:
                st.info("Choose a sample item or upload an image and save a demo label.")

if "alerts" in section_tabs:
    with section_tabs["alerts"]:
        st.subheader("SmartBin 360 · Alerts & notifications center")
        st.caption("Alerts are derived from the shared fleet telemetry. Resolve alerts individually or clear resolved history.")
        alerts = []
        for item in bins:
            if item["fill"] >= 95:
                alerts.append({
                    "id": f'{item["id"]}:overflow', "Bin": item["id"], "Severity": "Critical",
                    "Alert": "Critical overflow risk", "Details": f'{item["name"]} reached {item["fill"]}% capacity.',
                })
            elif item["fill"] >= 80:
                alerts.append({
                    "id": f'{item["id"]}:fill', "Bin": item["id"], "Severity": "High",
                    "Alert": "High fill level", "Details": f'{item["name"]} is at {item["fill"]}% capacity.',
                })
            if item["battery"] < 30:
                alerts.append({
                    "id": f'{item["id"]}:battery', "Bin": item["id"], "Severity": "Warning",
                    "Alert": "Low solar battery", "Details": f'{item["name"]} battery is at {item["battery"]}%.',
                })
        open_alerts = [alert for alert in alerts if alert["id"] not in st.session_state.resolved_alerts]
        st.metric("Open alerts", len(open_alerts))
        if open_alerts:
            for alert in open_alerts:
                alert_cols = st.columns([1, 4, 1])
                alert_cols[0].metric(alert["Severity"], alert["Bin"])
                alert_cols[1].markdown(f'**{alert["Alert"]}**  \n{alert["Details"]}')
                if alert_cols[2].button("Resolve", key=f'resolve_{alert["id"]}'):
                    enforce_permission("alerts")
                    st.session_state.resolved_alerts.add(alert["id"])
                    st.rerun()
        else:
            st.success("No open fleet alerts.")
        if st.session_state.resolved_alerts and st.button("Clear resolved alert history"):
            enforce_permission("alerts")
            st.session_state.resolved_alerts.clear()
            st.rerun()

if "analytics" in section_tabs:
    with section_tabs["analytics"]:
        st.subheader("Carbon reduction & waste analytics")
        chart_left, chart_right = st.columns(2)
        with chart_left:
            st.markdown("**AI material categorization**")
            st.bar_chart(pd.DataFrame({"Share (%)": [40, 30, 18, 12]}, index=["Organic & food", "Plastics", "Paper", "E-waste & glass"]), color="#10b981")
        with chart_right:
            st.markdown("**Monthly CO₂ emission reduction (kg)**")
            st.line_chart(pd.DataFrame({"CO₂ saved (kg)": [240, 310, 450, 520, 680, 890]}, index=["Jan", "Feb", "Mar", "Apr", "May", "Jun"]), color="#10b981")
        st.markdown("**Overflow history · weekly collections**")
        st.bar_chart(pd.DataFrame({"Overflow reports": [12, 8, 15, 19, 24, 31, 28], "Fuel saved (L)": [42, 50, 38, 30, 25, 18, 22]}, index=["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]))
        st.markdown("**Daily waste collected by campus location (kg)**")
        st.bar_chart(pd.DataFrame({"Collected (kg)": [210, 180, 350, 420, 150, 95]}, index=["Block A", "Library", "Cafeteria", "Hostel 3", "Stadium", "Admin"]))

if "telemetry" in section_tabs:
    with section_tabs["telemetry"]:
        st.subheader("IoT & ESP32 simulator")
        st.caption("Inspect fleet telemetry, inject simulated sensor values, and send sample MQTT pulses.")
        simulator_bin = st.selectbox("Select bin to simulate", [b["id"] for b in bins], key="mqtt_bin")
        simulator_selected = next(b for b in bins if b["id"] == simulator_bin)
        sensor_cols = st.columns(3)
        simulated_fill = sensor_cols[0].slider("Ultrasonic fill level (%)", 0, 100, simulator_selected["fill"], key=f"mqtt_fill_{simulator_bin}")
        battery_voltage = sensor_cols[1].slider(
            "Solar battery voltage", 3.0, 4.2,
            round(3.0 + simulator_selected["battery"] / 100 * 1.2, 2),
            step=0.01, key=f"mqtt_voltage_{simulator_bin}",
        )
        simulated_odor = sensor_cols[2].slider("MQ-135 gas / odor (PPM)", 10, 300, simulator_selected["odor"], key=f"mqtt_odor_{simulator_bin}")
        inject_col, pulse_col = st.columns(2)
        if auth.has_permission(user, "simulate_telemetry") and inject_col.button("Push simulated MQTT packet", width="stretch"):
            enforce_permission("simulate_telemetry")
            simulator_selected["fill"] = simulated_fill
            simulator_selected["battery"] = max(0, min(100, round((battery_voltage - 3.0) / 1.2 * 100)))
            simulator_selected["odor"] = simulated_odor
            simulator_selected["cleaned"] = "Telemetry updated just now"
            st.session_state.toast = f"MQTT telemetry updated for {simulator_bin}."
            st.rerun()
        if auth.has_permission(user, "simulate_telemetry") and pulse_col.button("Simulate live IoT pulse", width="stretch"):
            enforce_permission("simulate_telemetry")
            pulse_bin = random.choice(bins)
            pulse_bin["fill"] = min(100, pulse_bin["fill"] + random.randint(1, 14))
            pulse_bin["odor"] = min(300, pulse_bin["odor"] + random.randint(1, 8))
            pulse_bin["cleaned"] = "Auto pulse just now"
            st.session_state.toast = f'Live telemetry pulse received from {pulse_bin["id"]}.'
            st.rerun()
        st.dataframe(
            pd.DataFrame([{
                "Bin": b["id"], "MCU": "ESP32-WROOM-32U", "Firmware": "v2.4.1-build8",
                "Battery": f'{b["battery"]}%', "Solar": "Active / Charging" if b["battery"] > 35 else "Obstructed",
                "Ultrasonic (mm)": round(200 - b["fill"] * 1.8), "Gas (PPM)": b["odor"],
                "Core temp (°C)": b["temp"], "Status": "ONLINE",
            } for b in visible_bins]),
            hide_index=True,
            width="stretch",
        )
        with st.expander("ESP32 firmware blueprint"):
            st.code(
                """#include <WiFi.h>
    #include <PubSubClient.h>

    // Configure credentials securely on the device; never commit real secrets.
    const char* ssid = "<WIFI_SSID>";
    const char* password = "<WIFI_PASSWORD>";
    const char* mqtt_server = "<MQTT_HOST>";
    const int trigPin = 5;
    const int echoPin = 18;
    const int solarPin = 34;

    void setup() {
      Serial.begin(115200);
      pinMode(trigPin, OUTPUT);
      pinMode(echoPin, INPUT);
    }

    void loop() {
      // Read sensors and publish telemetry to the configured MQTT broker.
      delay(5000);
    }""",
                language="cpp",
            )

if "tasks" in section_tabs:
    with section_tabs["tasks"]:
        st.subheader("Field worker task & schedule manager")
        tasks_frame = pd.DataFrame([
            {**item, "Status": "Completed" if item["Task"] in st.session_state.completed_tasks else item["Status"]}
            for item in TASKS
        ])
        st.dataframe(tasks_frame, hide_index=True, width="stretch")
        incomplete_tasks = [item["Task"] for item in TASKS if item["Task"] not in st.session_state.completed_tasks]
        if incomplete_tasks:
            task = st.selectbox("Task to complete", incomplete_tasks)
            if auth.has_permission(user, "collect_bins") and st.button("Complete selected task"):
                enforce_permission("collect_bins")
                st.session_state.completed_tasks.add(task)
                st.rerun()
        else:
            st.success("All sample tasks have been completed.")

if "reports" in section_tabs:
    with section_tabs["reports"]:
        st.subheader("Community feedback & public reporting")
        st.caption("Submit a report about a damaged or overflowing smart bin.")
        with st.form("report_form", clear_on_submit=True):
            report_bin = st.selectbox("Nearest bin", [b["id"] for b in bins])
            report_issue = st.text_input("Complaint details", placeholder="Lid stuck or odor issue...")
            submitted = st.form_submit_button("Submit report")
        if submitted:
            if not report_issue.strip():
                st.error("Enter complaint details before submitting.")
            else:
                st.session_state.reports.insert(0, {
                    "Report": f"CMP-{random.randint(100, 999)}", "Bin": report_bin,
                    "Issue": report_issue.strip(), "Reported by": "You (Citizen)",
                    "Time": "Just now", "Status": "Pending",
                })
                st.success("Report submitted. The municipal team has been alerted.")
        st.dataframe(pd.DataFrame(st.session_state.reports), hide_index=True, width="stretch")

if "admin" in section_tabs:
    with section_tabs["admin"]:
        auth.render_admin_management(user)
