import streamlit as st
import pandas as pd
import openpyxl
import io
import re
from bs4 import BeautifulSoup
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

def parse_zap_html(file_bytes):
    """
    Hierarchical parser optimized for Checkmarx/OWASP ZAP HTML report architectures.
    Traverses nested list elements down to individual alerts tables.
    """
    soup = BeautifulSoup(file_bytes, 'html.parser')
    zap_rows = []
    
    alerts_section = soup.find('section', id='alerts')
    if not alerts_section:
        alerts_section = soup
        
    risk_groups = alerts_section.find_all('li', id=lambda x: x and x.startswith('alerts--risk-'))
    if not risk_groups:
        risk_groups = [h3.find_parent('li') for h3 in alerts_section.find_all('h3') if h3.find_parent('li')]
        
    for r_group in risk_groups:
        h3_text = ""
        h3_elem = r_group.find('h3')
        if h3_elem:
            h3_text = h3_elem.get_text().lower()
            
        risk_val = "Low"
        if "critical" in h3_text or "high" in h3_text:
            risk_val = "High"
        elif "medium" in h3_text:
            risk_val = "Medium"
            
        conf_val = "Low"
        if "high" in h3_text or "confirmed" in h3_text:
            conf_val = "High"
        elif "medium" in h3_text:
            conf_val = "Medium"
            
        h5_elements = r_group.find_all('h5')
        for h5 in h5_elements:
            alert_title = h5.get_text().strip()
            parent_li = h5.find_parent('li')
            if not parent_li:
                continue
                
            tables = parent_li.find_all('table', class_='alerts-table')
            for table in tables:
                row_data = {
                    "Source_Type": "ZAP", "Risk": risk_val, "Confidence_Str": conf_val,
                    "Host": "GET https://localhost", "Protocol": "Nil", "Port": "Nil",
                    "Name": alert_title, "Synopsis": "", "Solution": "", "See Also": "", "Output": ""
                }
                
                details_container = table.find_parent('details')
                if details_container:
                    summary_elem = details_container.find('summary')
                    if summary_elem:
                        url_span = summary_elem.find('span', class_='request-method-n-url')
                        if url_span:
                            row_data["Host"] = url_span.get_text().strip()
                        else:
                            row_data["Host"] = summary_elem.get_text().strip()
                else:
                    prev_details = table.find_previous('details')
                    if prev_details:
                        summary_elem = prev_details.find('summary')
                        if summary_elem:
                            row_data["Host"] = summary_elem.get_text().strip()
                            
                tr_elements = table.find_all('tr')
                for tr in tr_elements:
                    th = tr.find('th')
                    td = tr.find('td')
                    if not th or not td:
                        continue
                        
                    label = th.get_text().strip().lower()
                    
                    if 'description' in label:
                        row_data["Synopsis"] = td.get_text().strip()
                    elif 'solution' in label:
                        row_data["Solution"] = td.get_text().strip()
                    elif 'reference' in label:
                        links = [a['href'] for a in td.find_all('a', href=True)]
                        row_data["See Also"] = "\n".join(links)
                    elif 'response' in label:
                        pre_tag = td.find('pre')
                        if pre_tag:
                            row_data["Output"] = pre_tag.get_text().strip()
                        else:
                            row_data["Output"] = td.get_text().strip()
                            
                if row_data["Host"] and row_data["Risk"]:
                    zap_rows.append(row_data)
                    
    return pd.DataFrame(zap_rows)

# --- Streamlit Shell Configurations ---
st.set_page_config(page_title="Vulnerability Follow-up Plan Hub", layout="wide")
st.title("Consolidated Security Scan Follow-up Plan Generator")
st.write("Upload your files into their respective categories below. The tool compiles data seamlessly into the target layout.")

if "nessus_dataset" not in st.session_state:
    st.session_state["nessus_dataset"] = pd.DataFrame(columns=["Source_Type", "Risk", "Host", "Protocol", "Port", "Name", "Synopsis", "Solution", "See Also", "Confidence_Str", "Output"])
if "zap_dataset" not in st.session_state:
    st.session_state["zap_dataset"] = pd.DataFrame(columns=["Source_Type", "Risk", "Host", "Protocol", "Port", "Name", "Synopsis", "Solution", "See Also", "Confidence_Str", "Output"])
if "logged_nessus_files" not in st.session_state:
    st.session_state["logged_nessus_files"] = set()
if "logged_zap_files" not in st.session_state:
    st.session_state["logged_zap_files"] = set()

st.sidebar.header("App Settings")
project_name = st.sidebar.text_input("Project Name / Identifier", value="DH")
try:
    systems_tier = int(st.sidebar.number_input("Systems Tier (Integer Value)", min_value=1, max_value=10, value=2, step=1))
except ValueError:
    systems_tier = 1

if st.sidebar.button("Reset & Clear Upload Memory"):
    st.session_state["nessus_dataset"] = pd.DataFrame(columns=["Source_Type", "Risk", "Host", "Protocol", "Port", "Name", "Synopsis", "Solution", "See Also", "Confidence_Str", "Output"])
    st.session_state["zap_dataset"] = pd.DataFrame(columns=["Source_Type", "Risk", "Host", "Protocol", "Port", "Name", "Synopsis", "Solution", "See Also", "Confidence_Str", "Output"])
    st.session_state["logged_nessus_files"] = set()
    st.session_state["logged_zap_files"] = set()
    st.rerun()

col1, col2 = st.columns(2)

with col1:
    st.subheader("Nessus Scanning Data")
    uploaded_nessus = st.file_uploader("Upload raw Nessus CSV files", type=["csv"], accept_multiple_files=True, key="nessus_input")
    if uploaded_nessus:
        new_nessus = False
        for f in uploaded_nessus:
            if f.name not in st.session_state["logged_nessus_files"]:
                try:
                    temp_df = pd.read_csv(f, dtype={"Host": str, "Port": str})
                    temp_df["Source_Type"] = "Nessus"
                    headers = ["Source_Type", "Risk", "Host", "Protocol", "Port", "Name", "Synopsis", "Solution", "See Also", "Confidence_Str", "Output"]
                    for h in headers:
                        if h not in temp_df.columns:
                            temp_df[h] = ""
                    st.session_state["nessus_dataset"] = pd.concat([st.session_state["nessus_dataset"], temp_df[headers]], ignore_index=True)
                    st.session_state["logged_nessus_files"].add(f.name)
                    new_nessus = True
                except Exception as e:
                    st.error(f"Error parsing Nessus file '{f.name}': {e}")
        if new_nessus:
            st.rerun()

with col2:
    st.subheader("OWASP ZAP Data")
    uploaded_zap = st.file_uploader("Upload OWASP ZAP HTML reports", type=["html"], accept_multiple_files=True, key="zap_input")
    if uploaded_zap:
        new_zap = False
        for f in uploaded_zap:
            if f.name not in st.session_state["logged_zap_files"]:
                try:
                    file_bytes = f.read()
                    temp_df = parse_zap_html(file_bytes)
                    headers = ["Source_Type", "Risk", "Host", "Protocol", "Port", "Name", "Synopsis", "Solution", "See Also", "Confidence_Str", "Output"]
                    for h in headers:
                        if h not in temp_df.columns:
                            temp_df[h] = ""
                    st.session_state["zap_dataset"] = pd.concat([st.session_state["zap_dataset"], temp_df[headers]], ignore_index=True)
                    st.session_state["logged_zap_files"].add(f.name)
                    new_zap = True
                except Exception as e:
                    st.error(f"Error parsing ZAP report '{f.name}': {e}")
        if new_zap:
            st.rerun()

has_nessus = len(st.session_state["logged_nessus_files"]) > 0
has_zap = len(st.session_state["logged_zap_files"]) > 0

if not has_nessus and not has_zap:
    st.info("Awaiting file context inputs. Please populate target fields above.")
else:
    st.sidebar.markdown("---")
    st.sidebar.markdown("**Loaded Inventories:**")
    if has_nessus:
        st.sidebar.caption(f"Nessus CSVs ({len(st.session_state['logged_nessus_files'])} files)")
    if has_zap:
        st.sidebar.caption(f"ZAP HTMLs ({len(st.session_state['logged_zap_files'])} files)")

    nessus_df = st.session_state["nessus_dataset"].copy()
    zap_df = st.session_state["zap_dataset"].copy()
    
    processed_tracks = []
    
    # --- Process Nessus Memory Pool ---
    if not nessus_df.empty:
        for field in ["See Also", "Synopsis", "Solution", "Output", "Name", "Host"]:
            nessus_df[field] = nessus_df[field].fillna("").astype(str).str.strip()
            
        nessus_df = nessus_df.dropna(subset=["Risk", "Host", "Name"])
        nessus_df = nessus_df[~nessus_df["Name"].str.contains(r"certificate", case=False, na=False)]
        nessus_df = nessus_df[~nessus_df["Name"].str.contains(r"icmp.*timestamp", case=False, na=False)]
        nessus_df["Risk_Cleaned"] = nessus_df["Risk"].astype(str).str.strip()
        nessus_df = nessus_df[~nessus_df["Risk_Cleaned"].str.lower().isin(["none", "informational", "0", "nan", ""])]
        
        if not nessus_df.empty:
            nessus_df["Family"], nessus_df["Ver_Tuple"] = zip(*nessus_df["Name"].apply(get_vulnerability_family_and_version))
            nessus_df = nessus_df.sort_values(by=["Host", "Protocol", "Port", "Family", "Ver_Tuple"], ascending=[True, True, True, True, False])
            deduped_nessus = nessus_df.drop_duplicates(subset=["Host", "Protocol", "Port", "Family"], keep="first")
            
            grouped_nessus = deduped_nessus.groupby(["Protocol", "Port", "Name"], dropna=False)
            for (protocol, port, name), group in grouped_nessus:
                first_row = group.iloc[0]
                hosts_str = "\n".join(sorted(group["Host"].unique()))
                
                r_lower = str(first_row["Risk_Cleaned"]).lower()
                impact = 3 if 'critical' in r_lower or 'high' in r_lower else (2 if 'medium' in r_lower else 1)
                likelihood = 2 if impact >= 2 else 1
                
                processed_tracks.append({
                    "Source": "Nessus", "System/Asset ID": hosts_str, "Protocol": protocol, "Port": port,
                    "Security Domain Area": "Operation Security", "Risk Name/Observation": name,
                    "Vulnerability\n/Threat": first_row["Synopsis"], "Action plan": first_row["Solution"],
                    "Impact": impact, "Likelihood": likelihood, "Output": first_row["Output"], "Reference": first_row["See Also"]
                })
                
    # --- Process ZAP HTML Memory Pool ---
    if not zap_df.empty:
        for field in ["See Also", "Synopsis", "Solution", "Output", "Name", "Host"]:
            zap_df[field] = zap_df[field].fillna("").astype(str).str.strip()
            
        zap_df = zap_df.dropna(subset=["Risk", "Host", "Name"])
        zap_df = zap_df[~zap_df["Name"].str.contains(r"certificate", case=False, na=False)]
        zap_df = zap_df[~zap_df["Name"].str.contains(r"icmp.*timestamp", case=False, na=False)]
        zap_df["Risk_Cleaned"] = zap_df["Risk"].astype(str).str.strip()
        zap_df = zap_df[~zap_df["Risk_Cleaned"].str.lower().isin(["none", "informational", "0", "nan", ""])]
        
        if not zap_df.empty:
            grouped_zap = zap_df.groupby(["Protocol", "Port", "Name"], dropna=False)
            for (protocol, port, name), group in grouped_zap:
                first_row = group.iloc[0]
                urls_str = "\n".join(sorted(group["Host"].unique()))
                outputs_str = "\n".join([out for out in group["Output"].unique() if out])
                
                r_lower = str(first_row["Risk_Cleaned"]).lower()
                conf_str = str(first_row["Confidence_Str"]).lower()
                
                impact = 3 if 'high' in r_lower or 'critical' in r_lower else (2 if 'medium' in r_lower else 1)
                
                # Dynamic Multiplier Scale Rule: High/Confirmed = 2, Medium/Low = 1
                if 'high' in conf_str or 'confirmed' in conf_str:
                    likelihood = 2
                else:
                    likelihood = 1
                
                processed_tracks.append({
                    "Source": "ZAP", "System/Asset ID": urls_str, "Protocol": "Nil", "Port": "Nil",
                    "Security Domain Area": "Operation Security", "Risk Name/Observation": name,
                    "Vulnerability\n/Threat": first_row["Synopsis"], "Action plan": first_row["Solution"],
                    "Impact": impact, "Likelihood": likelihood, "Output": outputs_str, "Reference": first_row["See Also"]
                })
                
    if not processed_tracks:
        st.warning("No actionable vulnerabilities remaining after applying filters on current inputs.")
    else:
        for r in processed_tracks:
            r["Risk Rating"] = r["Impact"] * r["Likelihood"] * systems_tier
            r["Risk Rating/ Level"] = "Low" if r["Risk Rating"] <= 9 else ("Medium" if r["Risk Rating"] <= 18 else "High")
            
        nessus_final = [r for r in processed_tracks if r["Source"] == "Nessus"]
        zap_final = [r for r in processed_tracks if r["Source"] == "ZAP"]
        
        nessus_final.sort(key=lambda x: x["Risk Rating"], reverse=True)
        zap_final.sort(key=lambda x: x["Risk Rating"], reverse=True)
        
        excel_buffer = io.BytesIO()
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = "Follow-up Plan"
        
        ws.merge_cells("D1:H1")
        ws["D1"].value = "Follow-up Plan"
        ws["D1"].alignment = Alignment(horizontal="left", vertical="center")
        
        headers_blueprint = [
            'Observe /Findings#', 'System/Asset ID', 'Protocol', 'Port', 
            'Risk Treatment method (Acceptance / Reduction / Avoidance / Transfer)', 
            'Security Domain Area', 'Risk Name/Observation', 'Vulnerability\n/Threat', 
            'Action plan', 'Risk Rating/ Level', 'Impact', 'Likelihood', 
            'Systems Tier', 'Risk Rating', 'Target completion date\n(dd/mm/yyyy)', 
            'Status', 'Details of follow-up actions', 'Acutal Completion date\n(dd/mm/yyyy)', 
            'Reference', 'Output'
        ]
        
        for c_idx, title_text in enumerate(headers_blueprint, start=3):
            ws.cell(row=3, column=c_idx, value=title_text)
            
        total_rows_count = len(nessus_final) + len(zap_final)
        ws.auto_filter.ref = f"C3:V{total_rows_count + 3}"
        
        current_write_row = 4
        
        for i, r_data in enumerate(nessus_final):
            ws.cell(row=current_write_row, column=3, value=f"v{i + 1}")
            ws.cell(row=current_write_row, column=4, value=r_data["System/Asset ID"])
            ws.cell(row=current_write_row, column=5, value=r_data["Protocol"])
            ws.cell(row=current_write_row, column=6, value=r_data["Port"])
            ws.cell(row=current_write_row, column=8, value=r_data["Security Domain Area"])
            ws.cell(row=current_write_row, column=9, value=r_data["Risk Name/Observation"])
            ws.cell(row=current_write_row, column=10, value=r_data["Vulnerability\n/Threat"])
            ws.cell(row=current_write_row, column=11, value=r_data["Action plan"])
            ws.cell(row=current_write_row, column=12, value=r_data["Risk Rating/ Level"])
            ws.cell(row=current_write_row, column=13, value=r_data["Impact"])
            ws.cell(row=current_write_row, column=14, value=r_data["Likelihood"])
            ws.cell(row=current_write_row, column=15, value=systems_tier)
            ws.cell(row=current_write_row, column=16, value=r_data["Risk Rating"])
            ws.cell(row=current_write_row, column=21, value=r_data["Reference"])
            ws.cell(row=current_write_row, column=22, value=r_data["Output"])
            current_write_row += 1
            
        for i, r_data in enumerate(zap_final):
            ws.cell(row=current_write_row, column=3, value=f"A{i + 1}")
            ws.cell(row=current_write_row, column=4, value=r_data["System/Asset ID"])
            ws.cell(row=current_write_row, column=5, value=r_data["Protocol"])
            ws.cell(row=current_write_row, column=6, value=r_data["Port"])
            ws.cell(row=current_write_row, column=8, value=r_data["Security Domain Area"])
            ws.cell(row=current_write_row, column=9, value=r_data["Risk Name/Observation"])
            ws.cell(row=current_write_row, column=10, value=r_data["Vulnerability\n/Threat"])
            ws.cell(row=current_write_row, column=11, value=r_data["Action plan"])
            ws.cell(row=current_write_row, column=12, value=r_data["Risk Rating/ Level"])
            ws.cell(row=current_write_row, column=13, value=r_data["Impact"])
            ws.cell(row=current_write_row, column=14, value=r_data["Likelihood"])
            ws.cell(row=current_write_row, column=15, value=systems_tier)
            ws.cell(row=current_write_row, column=16, value=r_data["Risk Rating"])
            ws.cell(row=current_write_row, column=21, value=r_data["Reference"])
            ws.cell(row=current_write_row, column=22, value=r_data["Output"])
            current_write_row += 1
            
        st.success(f"Processing Complete! Consolidated entries into {total_rows_count} unique tracking rows.")
        
        center_align = Alignment(horizontal="center", vertical="top", wrap_text=True)
        left_align = Alignment(horizontal="left", vertical="top", wrap_text=True)
        
        for row in ws.iter_rows(min_row=3, max_row=total_rows_count + 3, min_col=3, max_col=22):
            for cell in row:
                if cell.column in [3, 5, 6, 8, 12, 13, 14, 15, 16]:
                    cell.alignment = center_align
                else:
                    cell.alignment = left_align
                    
        column_widths = {
            'C': 18, 'D': 25, 'E': 10, 'F': 10, 'G': 15, 'H': 18, 'I': 35, 'J': 45, 'K': 50, 
            'L': 18, 'M': 10, 'N': 10, 'O': 12, 'P': 12, 'Q': 15, 'R': 12, 'S': 20, 'T': 15, 'U': 30, 'V': 45
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
