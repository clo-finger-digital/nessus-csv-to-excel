import streamlit as st
import pandas as pd
import openpyxl
import io
import re
from openpyxl.utils import get_column_letter
from openpyxl.styles import Alignment


def extract_version(name_str):
    """Safely extracts version sequences (e.g., 2.4.58) for precise ranking."""
    if pd.isna(name_str):
        return (0,)
    match = re.search(r'(?:v|version\s*)?(\d+(?:\.\d+)+)', str(name_str), re.IGNORECASE)
    if match:
        try:
            return tuple(map(int, match.group(1).split('.')))
        except ValueError:
            return (0,)
    return (0,)


# --- Page Shell Configuration ---
st.set_page_config(page_title="Nessus Follow-up Plan Engine", layout="wide")
st.title("Executive Nessus Follow-up Plan Engine")
st.write(
    "Upload raw Nessus CSV files collectively or sequentially. Configure system tiers to compute impact matrix products matching your operational guidelines.")

# Initialize Persistent Session Cache Memory Pools
if "master_dataset" not in st.session_state:
    st.session_state["master_dataset"] = pd.DataFrame(
        columns=["Risk", "Host", "Protocol", "Port", "Name", "Synopsis", "Solution", "See Also"])
if "logged_filenames" not in st.session_state:
    st.session_state["logged_filenames"] = set()

# Sidebar Parameter Inputs Module
st.sidebar.header("System Environment Rules")
project_name = st.sidebar.text_input("Project Name / Identifier", value="DH")
try:
    systems_tier = int(
        st.sidebar.number_input("Systems Tier Multiplier Value", min_value=1, max_value=10, value=2, step=1))
except ValueError:
    systems_tier = 1

# Reset Workspace Actions Toggle
if st.sidebar.button("Reset & Clear Upload Memory"):
    st.session_state["master_dataset"] = pd.DataFrame(
        columns=["Risk", "Host", "Protocol", "Port", "Name", "Synopsis", "Solution", "See Also"])
    st.session_state["logged_filenames"] = set()
    st.rerun()

# Interactive Batch/Sequential Drag & Drop Entry Box
uploaded_files = st.file_uploader(
    "Choose raw Nessus scan files (Drop a batch together, or select files one-by-one over time)",
    type=["csv"],
    accept_multiple_files=True
)

# Process incoming stream files into the master data frame pool
if uploaded_files:
    headers_filter = ["Risk", "Host", "Protocol", "Port", "Name", "Synopsis", "Solution", "See Also"]
    new_data_loaded = False

    for f in uploaded_files:
        if f.name not in st.session_state["logged_filenames"]:
            try:
                # Read entire file without filtering to handle any weird extra columns safely
                temp_df = pd.read_csv(f, dtype={"Host": str, "Port": str})

                # Verify column existence; gracefully inject placeholders if omitted
                for column_header in headers_filter:
                    if column_header not in temp_df.columns:
                        temp_df[column_header] = ""

                # Crop down explicitly to the required schema columns
                temp_df = temp_df[headers_filter]

                # Append into the long-term state data frame block
                st.session_state["master_dataset"] = pd.concat([st.session_state["master_dataset"], temp_df],
                                                               ignore_index=True)
                st.session_state["logged_filenames"].add(f.name)
                new_data_loaded = True
            except Exception as e:
                st.error(f"Failed parsing file metadata for '{f.name}': {e}")

    if new_data_loaded:
        st.rerun()

# UI Diagnostics Display
if not st.session_state["logged_filenames"]:
    st.info("Awaiting file context inputs. Please upload one or more CSV reports above.")
else:
    st.sidebar.success(f"Staged Files Combined ({len(st.session_state['logged_filenames'])}):")
    for name in sorted(st.session_state["logged_filenames"]):
        st.sidebar.caption(f"• {name}")

    # Extract copy from session state cache to perform sorting calculations
    working_df = st.session_state["master_dataset"].copy()

    # 1. Clean missing blocks and sanitize out standard TLS/SSL certificate footprints
    working_df = working_df.dropna(subset=["Risk", "Host", "Name"])
    working_df = working_df[~working_df["Name"].str.contains(r"ssl|certificate|tls", case=False, na=False)]

    # Ensure See Also references are string-compatible and non-null
    working_df["See Also"] = working_df["See Also"].fillna("").astype(str).str.strip()

    # Normalize risk strings and filter out non-vulnerabilities
    working_df["Risk_Cleaned"] = working_df["Risk"].astype(str).str.strip()
    working_df = working_df[~working_df["Risk_Cleaned"].str.lower().isin(["none", "informational", "0", "nan", ""])]

    if working_df.empty:
        st.warning("No actionable vulnerabilities left after applying SSL and Informational filtering rules.")
    else:
        # Sort vulnerabilities so the highest patch version name sits at the top of group sets
        working_df["Ver_Tuple"] = working_df["Name"].apply(extract_version)
        working_df = working_df.sort_values(
            by=["Protocol", "Port", "Synopsis", "Solution", "See Also", "Risk_Cleaned", "Ver_Tuple", "Name"],
            ascending=[True, True, True, True, True, True, False, False]
        )

        # 2. Group findings by vulnerability definition keys
        grouped = working_df.groupby(["Protocol", "Port", "Synopsis", "Solution", "See Also", "Risk_Cleaned"],
                                     dropna=False)

        processed_rows = []
        for keys, group in grouped:
            protocol, port, synopsis, solution, see_also, risk = keys
            highest_version_name = group.iloc[0]["Name"]

            # Combine all unique IPs affected by this exact problem onto separate lines within one box
            unique_hosts = sorted(group["Host"].unique())
            hosts_multiline_str = "\n".join(unique_hosts)

            # Compute operational severity scoring metrics
            r_lower = str(risk).lower()
            if 'critical' in r_lower:
                impact, likelihood = 3, 2
            elif 'high' in r_lower:
                impact, likelihood = 2, 2
            elif 'medium' in r_lower:
                impact, likelihood = 2, 1
            else:
                impact, likelihood = 1, 1

            risk_rating = impact * likelihood * systems_tier

            if risk_rating <= 9:
                risk_level = "Low"
            elif risk_rating <= 18:
                risk_level = "Medium"
            else:
                risk_level = "High"

            processed_rows.append({
                "System/Asset ID": hosts_multiline_str,
                "Protocol": protocol,
                "Port": port,
                "Security Domain Area": "Operation Security",
                "Risk Name/Observation": highest_version_name,
                "Vulnerability\n/Threat": synopsis,
                "Action plan": solution,
                "Risk Rating/ Level": risk_level,
                "Impact": impact,
                "Likelihood": likelihood,
                "Systems Tier": systems_tier,
                "Risk Rating": risk_rating,
                "Reference": see_also
            })

        # Order rows by Risk Rating descending
        processed_rows.sort(key=lambda x: x["Risk Rating"], reverse=True)

        st.success(f"Successfully aggregated data down to {len(processed_rows)} unique consolidated issues.")

        # 3. Assemble binary openpyxl worksheet structure
        excel_buffer = io.BytesIO()
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = "Follow-up Plan"

        # Format Rule: Title in D1:H1 merged region
        ws.merge_cells("D1:H1")
        title_cell = ws["D1"]
        title_cell.value = "Follow-up Plan"
        title_cell.alignment = Alignment(horizontal="left", vertical="center")

        # Format Rule: Headers begin exactly at Column C, Row 3
        headers_blueprint = [
            'Observe /Findings#', 'System/Asset ID', 'Protocol', 'Port',
            'Risk Treatment method (Acceptance / Reduction / Avoidance / Transfer)',
            'Security Domain Area', 'Risk Name/Observation', 'Vulnerability\n/Threat',
            'Action plan', 'Risk Rating/ Level', 'Impact', 'Likelihood',
            'Systems Tier', 'Risk Rating', 'Target completion date\n(dd/mm/yyyy)',
            'Status', 'Details of follow-up actions', 'Acutal Completion date\n(dd/mm/yyyy)',
            'Reference'
        ]

        for c_idx, title_text in enumerate(headers_blueprint, start=3):
            ws.cell(row=3, column=c_idx, value=title_text)

        # Lock spreadsheet filtering parameters on the row 3 index headers range
        ws.auto_filter.ref = f"C3:U{len(processed_rows) + 3}"

        # Hydrate spreadsheet data fields starting at Row 4
        for r_offset, r_data in enumerate(processed_rows, start=4):
            ws.cell(row=r_offset, column=3, value=f"v{r_offset - 3}")  # Observe /Findings# Counter
            ws.cell(row=r_offset, column=4, value=r_data["System/Asset ID"])
            ws.cell(row=r_offset, column=5, value=r_data["Protocol"])
            ws.cell(row=r_offset, column=6, value=r_data["Port"])
            ws.cell(row=r_offset, column=8, value=r_data["Security Domain Area"])
            ws.cell(row=r_offset, column=9, value=r_data["Risk Name/Observation"])
            ws.cell(row=r_offset, column=10, value=r_data["Vulnerability\n/Threat"])
            ws.cell(row=r_offset, column=11, value=r_data["Action plan"])
            ws.cell(row=r_offset, column=12, value=r_data["Risk Rating/ Level"])
            ws.cell(row=r_offset, column=13, value=r_data["Impact"])
            ws.cell(row=r_offset, column=14, value=r_data["Likelihood"])
            ws.cell(row=r_offset, column=15, value=r_data["Systems Tier"])
            ws.cell(row=r_offset, column=16, value=r_data["Risk Rating"])
            ws.cell(row=r_offset, column=21, value=r_data["Reference"])

        # Configure wrapping alignments using clean Excel native system font styling rules
        center_align = Alignment(horizontal="center", vertical="top", wrap_text=True)
        left_align = Alignment(horizontal="left", vertical="top", wrap_text=True)

        for row in ws.iter_rows(min_row=3, max_row=len(processed_rows) + 3, min_col=3, max_col=21):
            for cell in row:
                if cell.column in [3, 5, 6, 8, 12, 13, 14, 15, 16]:
                    cell.alignment = center_align
                else:
                    cell.alignment = left_align

        # Apply standard column dimensions to protect layout fields from truncation
        column_widths = {
            'C': 18, 'D': 22, 'E': 10, 'F': 10, 'G': 15, 'H': 18, 'I': 35, 'J': 45, 'K': 50,
            'L': 18, 'M': 10, 'N': 10, 'O': 12, 'P': 12, 'Q': 15, 'R': 12, 'S': 20, 'T': 15, 'U': 30
        }
        for col_letter, width in column_widths.items():
            ws.column_dimensions[col_letter].width = width

        wb.save(excel_buffer)

        st.write("---")
        st.download_button(
            label="Download Structured Excel Follow-up Plan",
            data=excel_buffer.getvalue(),
            file_name=f"Follow up Plan - {project_name}.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )