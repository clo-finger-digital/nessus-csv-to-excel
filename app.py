import streamlit as st
import pandas as pd
import openpyxl
import io
import re
from openpyxl.utils import get_column_letter
from openpyxl.styles import Alignment

def parse_version_string(v_str):
    match = re.match(r'^(\d+(?:\.\d+)*)([a-z]*)$', str(v_str).strip(), re.IGNORECASE)
    if match:
        nums_str, letters = match.groups()
        nums = tuple(int(x) for x in nums_str.split('.'))
        letters = letters.lower()
        return (nums, len(letters), letters)
    return ((), 0, '')

def get_vulnerability_family_and_version(name_str):
    name_str = str(name_str).strip()
    if '<' in name_str:
        family = name_str.split('<')[0].strip()
    elif '<=' in name_str:
        family = name_str.split('<=')[0].strip()
    else:
        tokens = re.findall(r'\b\d+(?:\.\d+)+[a-z]*\b', name_str, re.IGNORECASE)
        family = name_str
        for t in tokens:
            family = family.replace(t, "[VERSION]")
            
    all_tokens = re.findall(r'\b\d+(?:\.\d+)+[a-z]*\b', name_str, re.IGNORECASE)
    if all_tokens:
        max_token = max(all_tokens, key=parse_version_string)
        max_version = parse_version_string(max_token)
    else:
        max_version = ((), 0, '')
        
    return family, max_version

# --- Streamlit Configurations ---
st.set_page_config(page_title="Nessus Follow-up Plan Hub", layout="wide")
st.title("Consolidated Nessus Follow-up Plan Generator")
st.write("Upload multiple Nessus CSV files collectively or sequentially. Configure parameters to compute impact matrix scores.")

if "master_dataset" not in st.session_state:
    st.session_state["master_dataset"] = pd.DataFrame(columns=["Risk", "Host", "Protocol", "Port", "Name", "Synopsis", "Solution", "See Also"])
if "logged_filenames" not in st.session_state:
    st.session_state["logged_filenames"] = set()

st.sidebar.header("App Settings")
project_name = st.sidebar.text_input("Project Name / Identifier", value="DH")
try:
    systems_tier = int(st.sidebar.number_input("Systems Tier (Integer Value)", min_value=1, max_value=10, value=2, step=1))
except ValueError:
    systems_tier = 1

if st.sidebar.button("🧹 Reset & Clear Upload Memory"):
    st.session_state["master_dataset"] = pd.DataFrame(columns=["Risk", "Host", "Protocol", "Port", "Name", "Synopsis", "Solution", "See Also"])
    st.session_state["logged_filenames"] = set()
    st.rerun()

uploaded_files = st.file_uploader("Upload raw Nessus CSV files (Drop files together or add one by one)", type=["csv"], accept_multiple_files=True)

if uploaded_files:
    headers = ["Risk", "Host", "Protocol", "Port", "Name", "Synopsis", "Solution", "See Also"]
    new_data_loaded = False
    
    for uploaded_file in uploaded_files:
        if uploaded_file.name not in st.session_state["logged_filenames"]:
            try:
                temp_df = pd.read_csv(uploaded_file, dtype={"Host": str, "Port": str})
                for h in headers:
                    if h not in temp_df.columns:
                        temp_df[h] = ""
                temp_df = temp_df[headers]
                st.session_state["master_dataset"] = pd.concat([st.session_state["master_dataset"], temp_df], ignore_index=True)
                st.session_state["logged_filenames"].add(uploaded_file.name)
                new_data_loaded = True
            except Exception as e:
                st.error(f"Error parsing {uploaded_file.name}: {e}")
                
    if new_data_loaded:
        st.rerun()

if not st.session_state["logged_filenames"]:
    st.info("Awaiting file context inputs. Please upload one or more CSV files above.")
else:
    st.sidebar.success(f"Staged Files ({len(st.session_state['logged_filenames'])}):")
    for name in sorted(st.session_state["logged_filenames"]):
        st.sidebar.caption(f"• {name}")
        
    master_df = st.session_state["master_dataset"].copy()
    
    master_df["See Also"] = master_df["See Also"].fillna("").astype(str).str.strip()
    master_df["Synopsis"] = master_df["Synopsis"].fillna("").astype(str).str.strip()
    master_df["Solution"] = master_df["Solution"].fillna("").astype(str).str.strip()
    
    # Cleansing & Certificate Exclusions
    master_df = master_df.dropna(subset=["Risk", "Host", "Name"])
    master_df = master_df[~master_df["Name"].str.contains(r"certificate", case=False, na=False)]
    
    master_df["Risk_Cleaned"] = master_df["Risk"].astype(str).str.strip()
    master_df = master_df[~master_df["Risk_Cleaned"].str.lower().isin(["none", "informational", "0", "nan", ""])]
    
    if master_df.empty:
        st.warning("No actionable vulnerabilities left after applying filters.")
    else:
        master_df["Family"], master_df["Ver_Tuple"] = zip(*master_df["Name"].apply(get_vulnerability_family_and_version))
        
        # Apply Per-Host Supersedence
        master_df = master_df.sort_values(
            by=["Host", "Protocol", "Port", "Family", "Ver_Tuple"], 
            ascending=[True, True, True, True, False]
        )
        deduped_master = master_df.drop_duplicates(subset=["Host", "Protocol", "Port", "Family"], keep="first")
        
        # Group by identical Protocol, Port, and exact Risk Name
        grouped = deduped_master.groupby(["Protocol", "Port", "Name"], dropna=False)
        
        processed_rows = []
        for (protocol, port, name), group in grouped:
            first_row = group.iloc[0]
            synopsis = first_row["Synopsis"]
            solution = first_row["Solution"]
            see_also = first_row["See Also"]
            risk = first_row["Risk_Cleaned"]
            
            unique_hosts = sorted(group["Host"].unique())
            hosts_multiline_str = "\n".join(unique_hosts)
            
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
                "Risk Name/Observation": name,
                "Vulnerability\n/Threat": synopsis,
                "Action plan": solution,
                "Risk Rating/ Level": risk_level,
                "Impact": impact,
                "Likelihood": likelihood,
                "Systems Tier": systems_tier,
                "Risk Rating": risk_rating,
                "Reference": see_also
            })
            
        processed_rows.sort(key=lambda x: x["Risk Rating"], reverse=True)
        st.success(f"Processing Complete! Aggregated into {len(processed_rows)} unique rows.")
        
        # Assemble Worksheet using openpyxl Defaults
        excel_buffer = io.BytesIO()
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = "Follow-up Plan"
        
        ws.merge_cells("D1:H1")
        title_cell = ws["D1"]
        title_cell.value = "Follow-up Plan"
        title_cell.alignment = Alignment(horizontal="left", vertical="center")
        
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
            
        ws.auto_filter.ref = f"C3:U{len(processed_rows) + 3}"
        
        for r_offset, r_data in enumerate(processed_rows, start=4):
            ws.cell(row=r_offset, column=3, value=f"v{r_offset - 3}")
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
            
        center_align = Alignment(horizontal="center", vertical="top", wrap_text=True)
        left_align = Alignment(horizontal="left", vertical="top", wrap_text=True)
        
        for row in ws.iter_rows(min_row=3, max_row=len(processed_rows) + 3, min_col=3, max_col=21):
            for cell in row:
                if cell.column in [3, 5, 6, 8, 12, 13, 14, 15, 16]:
                    cell.alignment = center_align
                else:
                    cell.alignment = left_align
                    
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
